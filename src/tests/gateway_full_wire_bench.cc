#include "base/package_api.h"

#include "packages/gateway/gateway.h"

#include <event2/buffer.h>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace {
using Clock = std::chrono::steady_clock;

constexpr int kRecipientsPerSlice = 64;
constexpr int kPlayers = 300;
constexpr int kRecipientsPerProducer = 297;
constexpr int kBatchLimit = 128;
constexpr int kScopeEpoch = 17;
constexpr int kExpectedRoomReservations = 1020;
constexpr int kExpectedAckFrames = kPlayers;
constexpr int kExpectedWireFrames =
    kExpectedRoomReservations + kExpectedAckFrames;
constexpr int kExpectedNativeSlices =
    (kExpectedRoomReservations + kRecipientsPerSlice - 1) /
    kRecipientsPerSlice;
constexpr LPC_INT kRoomServerSeqBase = 1000000;
constexpr LPC_INT kRoomMessageSeqBase = 2000000;
constexpr LPC_INT kRoomSentAtBase = 3000000;
constexpr LPC_INT kAckSeqBase = 4000000;
constexpr LPC_INT kAckServerSeqBase = 5000000;
constexpr LPC_INT kAckSentAtBase = 6000000;

void require(bool condition, const std::string &message) {
  if (!condition) {
    throw std::runtime_error(message);
  }
}

long long elapsed_ns(Clock::time_point start) {
  return std::chrono::duration_cast<std::chrono::nanoseconds>(Clock::now() - start)
      .count();
}

long long percentile(std::vector<long long> samples, double rank) {
  require(!samples.empty(), "percentile requires samples");
  std::sort(samples.begin(), samples.end());
  const auto position = std::max(
      0.0, std::ceil(rank * static_cast<double>(samples.size())) - 1.0);
  return samples[std::min(static_cast<size_t>(position), samples.size() - 1)];
}

std::string session_id_for(int recipient) {
  std::ostringstream session_id;
  session_id << "gw-full-wire-" << std::setw(3) << std::setfill('0')
             << recipient;
  return session_id.str();
}

std::string scope_id_for(int recipient) {
  return "player/full-wire/" + std::to_string(recipient);
}

std::unique_ptr<GatewaySession> make_session(int recipient, bool writable) {
  auto session = std::make_unique<GatewaySession>();
  session->session_id = session_id_for(recipient);
  session->master_fd = writable ? 1000 + recipient : -1;
  session->output_fifo_max_depth = 16;
  return session;
}

std::string stable_message_json(int producer) {
  nlohmann::json payload{
      {"schema_version", 1},
      {"channel", "main"},
      {"intent", "append"},
      {"priority", "normal"},
      {"reliability", "important"},
      {"display_mode", "instant"},
      {"ttl_ms", 30000},
      {"collapse_key", ""},
      {"text", "full-wire room observer event " + std::to_string(producer)},
      {"payload",
       {{"room_id", "room/full-wire"},
        {"producer_id", "producer-" + std::to_string(producer)}}},
  };
  return payload.dump();
}

std::string ack_protocol_frame(int producer) {
  nlohmann::json ack{
      {"producer", "producer-" + std::to_string(producer)},
      {"seq", kAckSeqBase + producer},
      {"server_seq", kAckServerSeqBase + producer},
      {"epoch", kScopeEpoch},
      {"sent_at", kAckSentAtBase + producer},
  };
  return "\x1bXKACKN" + ack.dump() + "\x1b\n";
}

bool recipient_is_excluded(int producer, int recipient) {
  const auto offset = (recipient - producer + kPlayers) % kPlayers;
  return offset < kPlayers - kRecipientsPerProducer;
}

struct WriterCapture {
  evbuffer *output{evbuffer_new()};
  std::vector<int> fds;
  uint64_t payload_bytes{0};

  WriterCapture() {
    if (!output) {
      throw std::bad_alloc();
    }
  }
  ~WriterCapture() {
    if (output) {
      evbuffer_free(output);
    }
  }
  WriterCapture(const WriterCapture &) = delete;
  WriterCapture &operator=(const WriterCapture &) = delete;
  WriterCapture(WriterCapture &&other) noexcept
      : output(std::exchange(other.output, nullptr)),
        fds(std::move(other.fds)),
        payload_bytes(other.payload_bytes) {}
  WriterCapture &operator=(WriterCapture &&other) noexcept {
    if (this != &other) {
      if (output) {
        evbuffer_free(output);
      }
      output = std::exchange(other.output, nullptr);
      fds = std::move(other.fds);
      payload_bytes = other.payload_bytes;
    }
    return *this;
  }
};

WriterCapture *g_writer_capture = nullptr;

int capture_writer(int fd, const char *data, size_t len) {
  if (!g_writer_capture || !g_writer_capture->output || !data || len == 0) {
    return 0;
  }
  try {
    g_writer_capture->fds.push_back(fd);
  } catch (const std::exception &) {
    return 0;
  }
  if (!gateway_append_framed_output_for_test(g_writer_capture->output, data,
                                              len)) {
    g_writer_capture->fds.pop_back();
    return 0;
  }
  g_writer_capture->payload_bytes += static_cast<uint64_t>(len);
  return 1;
}

class CaptureScope {
 public:
  explicit CaptureScope(WriterCapture *capture) {
    require(capture && !g_writer_capture, "invalid nested writer capture");
    g_writer_capture = capture;
  }
  ~CaptureScope() { g_writer_capture = nullptr; }
};

std::string copy_evbuffer(const evbuffer *buffer) {
  require(buffer != nullptr, "evbuffer is null");
  const auto length = evbuffer_get_length(buffer);
  std::string bytes(length, '\0');
  if (length > 0) {
    require(evbuffer_copyout(const_cast<evbuffer *>(buffer), bytes.data(),
                             length) == static_cast<ev_ssize_t>(length),
            "failed to copy framed evbuffer");
  }
  return bytes;
}

struct CapturedFrame {
  int fd{0};
  std::string payload;
};

std::vector<CapturedFrame> parse_capture(const WriterCapture &capture) {
  const auto bytes = copy_evbuffer(capture.output);
  std::vector<CapturedFrame> frames;
  size_t offset = 0;
  frames.reserve(capture.fds.size());
  while (offset < bytes.size()) {
    require(bytes.size() - offset >= sizeof(uint32_t),
            "truncated evbuffer frame header");
    const auto *head = reinterpret_cast<const unsigned char *>(bytes.data() + offset);
    const auto length = (static_cast<uint32_t>(head[0]) << 24) |
                        (static_cast<uint32_t>(head[1]) << 16) |
                        (static_cast<uint32_t>(head[2]) << 8) |
                        static_cast<uint32_t>(head[3]);
    offset += sizeof(uint32_t);
    require(length > 0 && bytes.size() - offset >= length,
            "invalid evbuffer frame length");
    require(frames.size() < capture.fds.size(),
            "evbuffer contains more frames than writer calls");
    frames.push_back(
        {capture.fds[frames.size()], bytes.substr(offset, length)});
    offset += length;
  }
  require(offset == bytes.size() && frames.size() == capture.fds.size(),
          "evbuffer/writer frame conservation mismatch");
  return frames;
}

void validate_framing_contract() {
  auto *buffer = evbuffer_new();
  require(buffer != nullptr, "failed to allocate framing contract buffer");
  const std::string seed = "seed";
  require(evbuffer_add(buffer, seed.data(), seed.size()) == 0,
          "failed to seed framing contract buffer");
  const auto before = copy_evbuffer(buffer);
  require(evbuffer_freeze(buffer, 0) == 0,
          "failed to freeze framing contract buffer");
  require(gateway_append_framed_output_for_test(buffer, "blocked", 7) == 0,
          "framing append unexpectedly succeeded on frozen buffer");
  require(copy_evbuffer(buffer) == before,
          "failed framing append changed readable bytes");
  require(evbuffer_unfreeze(buffer, 0) == 0,
          "failed to unfreeze framing contract buffer");
  evbuffer_drain(buffer, evbuffer_get_length(buffer));

  const std::string payload{"wire\0bytes", 10};
  require(gateway_append_framed_output_for_test(buffer, payload.data(),
                                                payload.size()) == 1,
          "production framing append failed");
  const auto framed = copy_evbuffer(buffer);
  require(framed.size() == sizeof(uint32_t) + payload.size(),
          "production framing byte count mismatch");
  const auto *head = reinterpret_cast<const unsigned char *>(framed.data());
  const auto length = (static_cast<uint32_t>(head[0]) << 24) |
                      (static_cast<uint32_t>(head[1]) << 16) |
                      (static_cast<uint32_t>(head[2]) << 8) |
                      static_cast<uint32_t>(head[3]);
  require(length == payload.size() &&
              framed.compare(sizeof(uint32_t), payload.size(), payload) == 0,
          "production framing bytes are not length+payload exact");
  evbuffer_free(buffer);
}

struct ExpectedRoomEvent {
  int producer{0};
  int recipient{0};
  LPC_INT message_seq{0};
  LPC_INT server_seq{0};
  LPC_INT epoch{0};
  LPC_INT sent_at{0};
};

struct RoomReservation {
  int recipient{0};
  uint64_t reservation_id{0};
  std::string scope_id;
  LPC_INT slot_epoch{0};
  LPC_INT slot_server_seq{0};
  std::vector<ExpectedRoomEvent> events;
};

enum class ExpectedFrameKind { kRoom, kAck };

struct ExpectedFrame {
  ExpectedFrameKind kind{ExpectedFrameKind::kRoom};
  uint64_t reservation_id{0};
  int producer{0};
};

struct PreparedWorkload {
  std::vector<std::unique_ptr<GatewaySession>> owned_sessions;
  std::vector<GatewaySession *> sessions;
  std::vector<RoomReservation> reservations;
  std::unordered_map<uint64_t, size_t> reservation_indices;
  std::vector<std::vector<ExpectedFrame>> expected_fifo;
  int producer_waves{0};
  int ack_frames{0};
};

RoomReservation &reservation_for(PreparedWorkload *workload,
                                 uint64_t reservation_id) {
  const auto found = workload->reservation_indices.find(reservation_id);
  require(found != workload->reservation_indices.end(),
          "missing expected room reservation");
  return workload->reservations[found->second];
}

void record_wave(PreparedWorkload *workload, int producer,
                 const std::vector<int> &recipients,
                 const std::vector<uint64_t> &existing_ids) {
  const auto count = recipients.size();
  std::vector<GatewaySession *> sessions;
  std::vector<LPC_INT> epochs(count, kScopeEpoch);
  std::vector<LPC_INT> message_seqs;
  sessions.reserve(count);
  message_seqs.reserve(count);
  for (const auto recipient : recipients) {
    sessions.push_back(workload->sessions[recipient]);
    message_seqs.push_back(kRoomMessageSeqBase + producer * 1000 + recipient);
  }

  const auto first_server_seq = kRoomServerSeqBase + producer * 1000;
  const auto sent_at = kRoomSentAtBase + producer;
  GatewaySessionBatchReservationResult result;
  require(gateway_reserve_and_append_preencoded_message_event_wave(
              sessions, existing_ids, first_server_seq, epochs, message_seqs,
              stable_message_json(producer), "room", sent_at, kBatchLimit,
              &result),
          "failed to reserve and append producer wave " +
              std::to_string(producer));
  require(result.reservation_ids.size() == count && result.reused.size() == count,
          "producer wave reservation shape mismatch");

  for (size_t index = 0; index < count; ++index) {
    const auto recipient = recipients[index];
    const auto reservation_id = result.reservation_ids[index];
    if (!result.reused[index]) {
      const auto record_index = workload->reservations.size();
      RoomReservation record;
      record.recipient = recipient;
      record.reservation_id = reservation_id;
      record.scope_id = scope_id_for(recipient);
      record.slot_epoch = kScopeEpoch;
      record.slot_server_seq =
          first_server_seq + static_cast<LPC_INT>(index * 2);
      workload->reservations.push_back(std::move(record));
      require(workload->reservation_indices
                  .emplace(reservation_id, record_index)
                  .second,
              "duplicate room reservation id");
      workload->expected_fifo[recipient].push_back(
          {ExpectedFrameKind::kRoom, reservation_id, producer});
    }
    auto &record = reservation_for(workload, reservation_id);
    record.events.push_back(
        {producer, recipient, message_seqs[index],
         first_server_seq + static_cast<LPC_INT>(index * 2 + 1),
         kScopeEpoch, sent_at});
    require(record.events.size() <= kBatchLimit,
            "room reservation exceeded native batch limit");
    require(gateway_pending_message_event_count(
                workload->sessions[recipient], reservation_id) ==
                record.events.size(),
            "pending room child conservation mismatch");
  }
}

PreparedWorkload prepare_slice(int event_count) {
  require(event_count > 0 && event_count <= kBatchLimit,
          "event count outside native batch limit");
  PreparedWorkload workload;
  workload.owned_sessions.reserve(kRecipientsPerSlice);
  workload.sessions.reserve(kRecipientsPerSlice);
  workload.expected_fifo.resize(kRecipientsPerSlice);
  for (int recipient = 0; recipient < kRecipientsPerSlice; ++recipient) {
    auto session = make_session(recipient, true);
    workload.sessions.push_back(session.get());
    workload.owned_sessions.push_back(std::move(session));
  }

  std::vector<uint64_t> active_ids(kRecipientsPerSlice, 0);
  std::vector<int> recipients(kRecipientsPerSlice);
  for (int recipient = 0; recipient < kRecipientsPerSlice; ++recipient) {
    recipients[recipient] = recipient;
  }
  for (int producer = 0; producer < event_count; ++producer) {
    std::vector<uint64_t> existing_ids(kRecipientsPerSlice, 0);
    for (int recipient = 0; recipient < kRecipientsPerSlice; ++recipient) {
      if (active_ids[recipient] > 0 &&
          gateway_pending_message_event_count(workload.sessions[recipient],
                                              active_ids[recipient]) <
              kBatchLimit) {
        existing_ids[recipient] = active_ids[recipient];
      }
    }
    record_wave(&workload, producer, recipients, existing_ids);
    for (int recipient = 0; recipient < kRecipientsPerSlice; ++recipient) {
      active_ids[recipient] =
          workload.expected_fifo[recipient].back().reservation_id;
    }
  }
  require(workload.reservations.size() == kRecipientsPerSlice,
          "slice did not retain one room reservation per recipient");
  workload.producer_waves = event_count;
  return workload;
}

PreparedWorkload prepare_exact_wave() {
  PreparedWorkload workload;
  workload.owned_sessions.reserve(kPlayers);
  workload.sessions.reserve(kPlayers);
  workload.expected_fifo.resize(kPlayers);
  for (int recipient = 0; recipient < kPlayers; ++recipient) {
    auto session = make_session(recipient, false);
    workload.sessions.push_back(session.get());
    workload.owned_sessions.push_back(std::move(session));
  }

  std::vector<uint64_t> active_ids(kPlayers, 0);
  for (int producer = 0; producer < kPlayers; ++producer) {
    const auto ack = ack_protocol_frame(producer);
    require(gateway_enqueue_session_protocol_output(
                workload.sessions[producer], ack.data(), ack.size()) == 1,
            "failed to enqueue producer ACK " + std::to_string(producer));
    workload.expected_fifo[producer].push_back(
        {ExpectedFrameKind::kAck, 0, producer});
    workload.ack_frames++;

    std::vector<int> recipients;
    std::vector<uint64_t> existing_ids;
    recipients.reserve(kRecipientsPerProducer);
    existing_ids.reserve(kRecipientsPerProducer);
    for (int recipient = 0; recipient < kPlayers; ++recipient) {
      if (recipient_is_excluded(producer, recipient)) {
        continue;
      }
      recipients.push_back(recipient);
      const auto active_id = active_ids[recipient];
      existing_ids.push_back(
          active_id > 0 &&
                  gateway_pending_message_event_count(
                      workload.sessions[recipient], active_id) < kBatchLimit
              ? active_id
              : 0);
    }
    require(recipients.size() == kRecipientsPerProducer,
            "producer recipient count mismatch");
    record_wave(&workload, producer, recipients, existing_ids);
    for (size_t index = 0; index < recipients.size(); ++index) {
      active_ids[recipients[index]] =
          reservation_for(&workload,
                          workload.expected_fifo[recipients[index]].back()
                              .reservation_id)
              .reservation_id;
    }
    workload.producer_waves++;
  }

  for (int recipient = 0; recipient < kPlayers; ++recipient) {
    workload.sessions[recipient]->master_fd = 1000 + recipient;
  }
  require(workload.producer_waves == kPlayers &&
              workload.ack_frames == kExpectedAckFrames,
          "exact producer/ACK conservation mismatch");
  require(workload.reservations.size() == kExpectedRoomReservations,
          "exact room reservation count is " +
              std::to_string(workload.reservations.size()) + " not " +
              std::to_string(kExpectedRoomReservations));
  uint64_t logical_messages = 0;
  for (const auto &record : workload.reservations) {
    logical_messages += record.events.size();
  }
  require(logical_messages ==
              static_cast<uint64_t>(kPlayers * kRecipientsPerProducer),
          "exact logical room message conservation mismatch");
  return workload;
}

struct FilledWorkload {
  long long elapsed_ns{0};
  int native_slices{0};
  WriterCapture capture;
};

FilledWorkload fill_workload(PreparedWorkload *workload) {
  require(workload && !workload->reservations.empty(),
          "cannot fill empty workload");
  FilledWorkload filled;
  CaptureScope capture_scope(&filled.capture);
  const auto started = Clock::now();
  for (size_t start = 0; start < workload->reservations.size();
       start += kRecipientsPerSlice) {
    const auto end =
        std::min(start + kRecipientsPerSlice, workload->reservations.size());
    std::vector<GatewaySession *> sessions;
    std::vector<uint64_t> reservation_ids;
    std::vector<std::string> scope_ids;
    std::vector<LPC_INT> slot_epochs;
    sessions.reserve(end - start);
    reservation_ids.reserve(end - start);
    scope_ids.reserve(end - start);
    slot_epochs.reserve(end - start);
    for (size_t index = start; index < end; ++index) {
      const auto &record = workload->reservations[index];
      sessions.push_back(workload->sessions[record.recipient]);
      reservation_ids.push_back(record.reservation_id);
      scope_ids.push_back(record.scope_id);
      slot_epochs.push_back(record.slot_epoch);
    }
    GatewayPendingMessageEventBatchFillResult result;
    require(gateway_fill_pending_message_event_batches_with_writer(
                sessions, reservation_ids, scope_ids, slot_epochs,
                capture_writer, &result),
            "native full-wire batch fill failed");
    require(result.filled.size() == end - start &&
                result.event_counts.size() == end - start &&
                result.slot_server_seqs.size() == end - start,
            "native full-wire fill result shape mismatch");
    for (size_t index = 0; index < end - start; ++index) {
      const auto &record = workload->reservations[start + index];
      require(result.filled[index] &&
                  result.event_counts[index] ==
                      static_cast<LPC_INT>(record.events.size()) &&
                  result.slot_server_seqs[index] == record.slot_server_seq,
              "native full-wire fill result conservation mismatch");
    }
    filled.native_slices++;
  }
  filled.elapsed_ns = ::elapsed_ns(started);
  for (const auto *session : workload->sessions) {
    require(session->output_fifo.empty(),
            "session FIFO did not drain after full-wire fill");
  }
  return filled;
}

std::string protocol_payload(const nlohmann::json &outer,
                             const std::string &session_id) {
  require(outer.is_object() && outer.size() == 3 &&
              outer.value("type", "") == "output" &&
              outer.value("cid", "") == session_id && outer.contains("data") &&
              outer["data"].is_string(),
          "invalid southbound output envelope");
  return outer["data"].get<std::string>();
}

nlohmann::json parse_protocol_json(const std::string &data,
                                   std::string_view prefix) {
  constexpr std::string_view suffix = "\x1b\n";
  require(data.size() > prefix.size() + suffix.size() &&
              data.compare(0, prefix.size(), prefix) == 0 &&
              data.compare(data.size() - suffix.size(), suffix.size(), suffix) ==
                  0,
          "invalid protocol frame boundary");
  return nlohmann::json::parse(data.substr(
      prefix.size(), data.size() - prefix.size() - suffix.size()));
}

void validate_room_event(const nlohmann::json &event,
                         const ExpectedRoomEvent &expected,
                         LPC_INT expected_server_seq) {
  require(event.is_object() &&
              event.value("text", "") ==
                  "full-wire room observer event " +
                      std::to_string(expected.producer) &&
              event.value("seq", static_cast<LPC_INT>(0)) ==
                  expected.message_seq &&
              event.value("timestamp", static_cast<LPC_INT>(0)) ==
                  expected.sent_at,
          "room event stable/dynamic field mismatch");
  require(event.contains("payload") && event["payload"].is_object() &&
              event["payload"].value("room_id", "") == "room/full-wire" &&
              event["payload"].value("producer_id", "") ==
                  "producer-" + std::to_string(expected.producer),
          "room event producer payload mismatch");
  require(event.contains("scope") && event["scope"].is_object() &&
              event["scope"].value("type", "") == "room" &&
              event["scope"].value("id", "") ==
                  scope_id_for(expected.recipient),
          "room event scope mismatch");
  require(event.contains("meta") && event["meta"].is_object() &&
              event["meta"].value("stream", "") == "message" &&
              event["meta"].value("server_seq", static_cast<LPC_INT>(0)) ==
                  expected_server_seq &&
              event["meta"].value("epoch", static_cast<LPC_INT>(-1)) ==
                  expected.epoch &&
              event["meta"].value("sent_at", static_cast<LPC_INT>(0)) ==
                  expected.sent_at,
          "room event meta mismatch");
}

size_t validate_room_frame(const std::string &data,
                           const RoomReservation &record) {
  require(!record.events.empty(), "expected room reservation is empty");
  if (record.events.size() == 1) {
    const auto event = parse_protocol_json(data, "\x1bXKMSGE");
    validate_room_event(event, record.events.front(), record.slot_server_seq);
    return 1;
  }

  const auto batch = parse_protocol_json(data, "\x1bXKBACH");
  require(batch.is_object() && batch.contains("messages") &&
              batch["messages"].is_array() &&
              batch["messages"].size() == record.events.size(),
          "room batch child conservation mismatch");
  require(batch.contains("meta") && batch["meta"].is_object() &&
              batch["meta"].value("server_seq", static_cast<LPC_INT>(0)) ==
                  record.slot_server_seq &&
              batch["meta"].value("epoch", static_cast<LPC_INT>(-1)) ==
                  record.slot_epoch,
          "room batch slot meta mismatch");
  for (size_t index = 0; index < record.events.size(); ++index) {
    const auto &child = batch["messages"][index];
    require(child.is_object() && child.value("type", "") == "MSGE" &&
                child.contains("payload") && child["payload"].is_object(),
            "room batch child shape mismatch");
    validate_room_event(child["payload"], record.events[index],
                        record.events[index].server_seq);
  }
  return record.events.size();
}

void validate_ack_frame(const std::string &data, int producer) {
  const auto ack = parse_protocol_json(data, "\x1bXKACKN");
  require(ack.is_object() &&
              ack.value("producer", "") ==
                  "producer-" + std::to_string(producer) &&
              ack.value("seq", static_cast<LPC_INT>(0)) ==
                  kAckSeqBase + producer &&
              ack.value("server_seq", static_cast<LPC_INT>(0)) ==
                  kAckServerSeqBase + producer &&
              ack.value("epoch", static_cast<LPC_INT>(-1)) == kScopeEpoch &&
              ack.value("sent_at", static_cast<LPC_INT>(0)) ==
                  kAckSentAtBase + producer,
          "ACK dynamic fields mismatch");
}

struct ValidationCounts {
  uint64_t room_frames{0};
  uint64_t ack_frames{0};
  uint64_t room_children{0};
};

ValidationCounts validate_workload(const PreparedWorkload &workload,
                                   const FilledWorkload &filled) {
  const auto frames = parse_capture(filled.capture);
  std::vector<std::vector<const CapturedFrame *>> by_recipient(
      workload.sessions.size());
  for (const auto &frame : frames) {
    const auto recipient = frame.fd - 1000;
    require(recipient >= 0 &&
                recipient < static_cast<int>(workload.sessions.size()),
            "writer fd is outside the workload session set");
    by_recipient[recipient].push_back(&frame);
  }

  ValidationCounts counts;
  for (size_t recipient = 0; recipient < workload.sessions.size(); ++recipient) {
    const auto &expected = workload.expected_fifo[recipient];
    const auto &actual = by_recipient[recipient];
    require(actual.size() == expected.size(),
            "per-session FIFO frame count mismatch for " +
                session_id_for(static_cast<int>(recipient)));
    for (size_t index = 0; index < expected.size(); ++index) {
      const auto outer = nlohmann::json::parse(actual[index]->payload);
      const auto data = protocol_payload(
          outer, session_id_for(static_cast<int>(recipient)));
      if (expected[index].kind == ExpectedFrameKind::kAck) {
        validate_ack_frame(data, expected[index].producer);
        counts.ack_frames++;
      } else {
        const auto &record = workload.reservations.at(
            workload.reservation_indices.at(expected[index].reservation_id));
        counts.room_children += validate_room_frame(data, record);
        counts.room_frames++;
      }
    }
    require(workload.sessions[recipient]->output_fifo_flushed == expected.size(),
            "per-session FIFO flush conservation mismatch");
  }
  require(counts.room_frames + counts.ack_frames == frames.size(),
          "validated frame conservation mismatch");
  return counts;
}

void validate_lightweight(const PreparedWorkload &workload,
                          const FilledWorkload &filled,
                          size_t expected_frames, int expected_native_slices) {
  require(filled.capture.fds.size() == expected_frames,
          "writer frame count mismatch");
  require(filled.native_slices == expected_native_slices,
          "native slice count mismatch");
  for (size_t recipient = 0; recipient < workload.sessions.size(); ++recipient) {
    require(workload.sessions[recipient]->output_fifo.empty() &&
                workload.sessions[recipient]->output_fifo_flushed ==
                    workload.expected_fifo[recipient].size(),
            "lightweight FIFO conservation mismatch");
  }
}

void write_capture(const std::filesystem::path &path,
                   const WriterCapture &capture) {
  std::filesystem::create_directories(path.parent_path());
  std::ofstream output(path, std::ios::binary | std::ios::trunc);
  require(output.is_open(), "failed to create framed corpus: " + path.string());
  const auto bytes = copy_evbuffer(capture.output);
  output.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
  require(output.good(), "failed to write framed corpus: " + path.string());
}

nlohmann::json samples_json(const std::vector<long long> &samples) {
  return nlohmann::json{
      {"count", samples.size()},
      {"p50_ns", percentile(samples, 0.50)},
      {"p95_ns", percentile(samples, 0.95)},
      {"p99_ns", percentile(samples, 0.99)},
      {"max_ns", *std::max_element(samples.begin(), samples.end())},
      {"raw_ns", samples},
  };
}

nlohmann::json run_slice_case(int event_count, int warmups, int samples,
                              const std::filesystem::path &corpus_dir) {
  for (int index = 0; index < warmups; ++index) {
    auto prepared = prepare_slice(event_count);
    auto filled = fill_workload(&prepared);
    validate_lightweight(prepared, filled, kRecipientsPerSlice, 1);
  }

  std::vector<long long> sample_ns;
  sample_ns.reserve(samples);
  uint64_t writer_payload_bytes = 0;
  uint64_t framed_wire_bytes = 0;
  for (int index = 0; index < samples; ++index) {
    auto prepared = prepare_slice(event_count);
    auto filled = fill_workload(&prepared);
    validate_lightweight(prepared, filled, kRecipientsPerSlice, 1);
    sample_ns.push_back(filled.elapsed_ns);
    writer_payload_bytes = filled.capture.payload_bytes;
    framed_wire_bytes = evbuffer_get_length(filled.capture.output);
  }

  auto corpus_prepared = prepare_slice(event_count);
  auto corpus_filled = fill_workload(&corpus_prepared);
  const auto validated = validate_workload(corpus_prepared, corpus_filled);
  require(validated.room_frames == kRecipientsPerSlice &&
              validated.ack_frames == 0 &&
              validated.room_children ==
                  static_cast<uint64_t>(kRecipientsPerSlice * event_count),
          "slice deep validation conservation mismatch");
  const auto corpus_path =
      corpus_dir / (std::to_string(event_count) + ".frames");
  write_capture(corpus_path, corpus_filled.capture);

  return nlohmann::json{
      {"event_count", event_count},
      {"recipients_per_slice", kRecipientsPerSlice},
      {"writer_frames_per_slice", kRecipientsPerSlice},
      {"logical_messages_per_slice", kRecipientsPerSlice * event_count},
      {"writer_payload_bytes_per_slice", writer_payload_bytes},
      {"framed_wire_bytes_per_slice", framed_wire_bytes},
      {"child_semantics_validated", true},
      {"slice_fill", samples_json(sample_ns)},
      {"corpus", corpus_path.string()},
  };
}

nlohmann::json run_exact_wave(int warmups, int samples,
                              const std::filesystem::path &corpus_dir) {
  for (int index = 0; index < warmups; ++index) {
    auto prepared = prepare_exact_wave();
    auto filled = fill_workload(&prepared);
    validate_lightweight(prepared, filled, kExpectedWireFrames,
                         kExpectedNativeSlices);
  }

  std::vector<long long> sample_ns;
  sample_ns.reserve(samples);
  for (int index = 0; index < samples; ++index) {
    auto prepared = prepare_exact_wave();
    auto filled = fill_workload(&prepared);
    validate_lightweight(prepared, filled, kExpectedWireFrames,
                         kExpectedNativeSlices);
    sample_ns.push_back(filled.elapsed_ns);
  }

  auto corpus_prepared = prepare_exact_wave();
  auto corpus_filled = fill_workload(&corpus_prepared);
  const auto validated = validate_workload(corpus_prepared, corpus_filled);
  require(validated.room_frames == kExpectedRoomReservations &&
              validated.ack_frames == kExpectedAckFrames &&
              validated.room_children ==
                  static_cast<uint64_t>(kPlayers * kRecipientsPerProducer),
          "exact wave deep validation conservation mismatch");
  const auto corpus_path = corpus_dir / "exact-wave.frames";
  write_capture(corpus_path, corpus_filled.capture);

  return nlohmann::json{
      {"producer_waves", kPlayers},
      {"recipients_per_producer", kRecipientsPerProducer},
      {"logical_room_messages", kPlayers * kRecipientsPerProducer},
      {"room_reservations", kExpectedRoomReservations},
      {"room_frames", kExpectedRoomReservations},
      {"ack_frames", kExpectedAckFrames},
      {"writer_frames", kExpectedWireFrames},
      {"native_slices", kExpectedNativeSlices},
      {"fifo_ack_interleaved", true},
      {"child_semantics_validated", true},
      {"framed_wire_bytes", evbuffer_get_length(corpus_filled.capture.output)},
      {"whole_wave_fill", samples_json(sample_ns)},
      {"corpus", corpus_path.string()},
  };
}

int parse_positive(const std::string &value, const char *name) {
  size_t consumed = 0;
  const auto parsed = std::stoi(value, &consumed);
  if (consumed != value.size() || parsed <= 0) {
    throw std::runtime_error(std::string(name) + " must be positive");
  }
  return parsed;
}

}  // namespace

int main(int argc, char **argv) {
  std::filesystem::path json_path;
  std::filesystem::path corpus_dir;
  int warmups = 3;
  int slice_samples = 101;
  int wave_samples = 101;

  try {
    for (int index = 1; index < argc; ++index) {
      const std::string arg = argv[index];
      if (arg == "--json" && index + 1 < argc) {
        json_path = argv[++index];
      } else if (arg == "--corpus-dir" && index + 1 < argc) {
        corpus_dir = argv[++index];
      } else if (arg == "--warmups" && index + 1 < argc) {
        warmups = parse_positive(argv[++index], "warmups");
      } else if (arg == "--slice-samples" && index + 1 < argc) {
        slice_samples = parse_positive(argv[++index], "slice samples");
      } else if (arg == "--wave-samples" && index + 1 < argc) {
        wave_samples = parse_positive(argv[++index], "wave samples");
      } else if (arg == "--help") {
        std::cout
            << "usage: gateway_full_wire_bench --json PATH --corpus-dir DIR "
               "[--warmups N] [--slice-samples N] [--wave-samples N]\n";
        return 0;
      } else {
        throw std::runtime_error("unknown or incomplete argument: " + arg);
      }
    }
    require(!json_path.empty(), "--json is required");
    require(!corpus_dir.empty(), "--corpus-dir is required");
    validate_framing_contract();

    json_path = std::filesystem::absolute(json_path);
    corpus_dir = std::filesystem::absolute(corpus_dir);
    std::filesystem::create_directories(json_path.parent_path());
    std::filesystem::create_directories(corpus_dir);

    nlohmann::json report{
        {"schema", "xkx_gateway_full_wire_fluffos_v2"},
        {"component", "fluffos_pending_room_batch"},
        {"measurement_boundary",
         "production_reservation+pending_batch_projection+outer_output_json+fifo_fill+production_evbuffer_framing"},
        {"players", kPlayers},
        {"recipients_per_producer", kRecipientsPerProducer},
        {"logical_room_messages", kPlayers * kRecipientsPerProducer},
        {"batch_limit", kBatchLimit},
        {"warmups", warmups},
        {"framing_contract",
         {{"single_commit", true},
          {"failure_zero_append", true},
          {"length_and_payload_byte_exact", true}}},
        {"cases", nlohmann::json::array()},
    };
    report["cases"].push_back(
        run_slice_case(104, warmups, slice_samples, corpus_dir));
    report["cases"].push_back(
        run_slice_case(128, warmups, slice_samples, corpus_dir));
    report["exact_wave"] = run_exact_wave(warmups, wave_samples, corpus_dir);

    std::ofstream output(json_path, std::ios::trunc);
    require(output.is_open(), "failed to create C++ benchmark report");
    output << report.dump(2) << '\n';
    require(output.good(), "failed to write C++ benchmark report");
    std::cout << report.dump() << '\n';
    return 0;
  } catch (const std::exception &error) {
    g_writer_capture = nullptr;
    std::cerr << "gateway_full_wire_bench failed: " << error.what() << '\n';
    return 1;
  }
}
