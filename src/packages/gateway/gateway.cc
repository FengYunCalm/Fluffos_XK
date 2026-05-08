#include "base/package_api.h"

#include "gateway.h"

#include "backend.h"
#include "base/internal/rc.h"

#include <arpa/inet.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/event.h>
#include <event2/listener.h>

#include <nlohmann/json.hpp>

#include <cstring>
#include <ctime>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

int g_gateway_debug = 0;
size_t g_gateway_max_packet_size = 1024 * 1024;
int g_gateway_max_masters = 16;
int g_gateway_max_sessions = 4096;
int g_gateway_heartbeat_interval = 15;
int g_gateway_heartbeat_timeout = 45;

namespace {
constexpr int kGatewayDefaultMaxMasters = 16;
constexpr int kGatewayDefaultHeartbeatInterval = 15;
constexpr int kGatewayDefaultHeartbeatTimeout = 45;
constexpr int kGatewayMaxJsonDepth = 20;

evconnlistener *g_gateway_listener = nullptr;
event *g_gateway_heartbeat_timer = nullptr;
std::unordered_map<int, std::unique_ptr<GatewayMaster>> g_gateway_masters;
int g_gateway_next_fd = 1;
int g_gateway_listen_port = 0;
time_t g_gateway_started_at = 0;

void gateway_handle_hello(int fd, const nlohmann::json &msg);
void gateway_handle_login(int fd, const nlohmann::json &msg);
void gateway_handle_data(int fd, const nlohmann::json &msg);
void gateway_handle_discon(int fd, const nlohmann::json &msg);
void gateway_handle_sys(int fd, const nlohmann::json &msg);

void gateway_stop_heartbeat_timer();
int gateway_start_heartbeat_timer();

bool gateway_object_valid_local(object_t *ob) {
  return ob && !(ob->flags & O_DESTRUCTED) && ob->obname && ob->obname[0] != '\0';
}

void gateway_apply_receive(object_t *user, svalue_t *data_sv) {
  if (!gateway_object_valid_local(user) || !data_sv) {
    return;
  }

  save_command_giver(user);
  current_interactive = user;
  set_eval(max_eval_cost);
  push_svalue(data_sv);
  safe_apply("gateway_receive", user, 1, ORIGIN_DRIVER);
  current_interactive = nullptr;
  restore_command_giver();
}

svalue_t json_to_gateway_svalue(const nlohmann::json &value) {
  svalue_t sv = {};

  if (value.is_object()) {
    auto count = static_cast<int>(value.size());
    array_t *keys = allocate_array(count);
    array_t *values = allocate_array(count);
    int i = 0;
    for (const auto &entry : value.items()) {
      keys->item[i].type = T_STRING;
      keys->item[i].subtype = STRING_MALLOC;
      keys->item[i].u.string = string_copy(entry.key().c_str(), "gateway_json_key");
      auto item = json_to_gateway_svalue(entry.value());
      assign_svalue_no_free(&values->item[i], &item);
      free_svalue(&item, "gateway_json_value");
      i++;
    }
    sv.type = T_MAPPING;
    sv.u.map = mkmapping(keys, values);
    free_array(keys);
    free_array(values);
    return sv;
  }
  if (value.is_array()) {
    auto count = static_cast<int>(value.size());
    sv.type = T_ARRAY;
    sv.u.arr = allocate_array(count);
    for (int i = 0; i < count; i++) {
      auto item = json_to_gateway_svalue(value[i]);
      assign_svalue_no_free(&sv.u.arr->item[i], &item);
      free_svalue(&item, "gateway_json_array_item");
    }
    return sv;
  }
  if (value.is_string()) {
    sv.type = T_STRING;
    sv.subtype = STRING_MALLOC;
    sv.u.string = string_copy(value.get_ref<const std::string &>().c_str(), "gateway_json_string");
    return sv;
  }
  if (value.is_boolean()) {
    sv.type = T_NUMBER;
    sv.u.number = value.get<bool>() ? 1 : 0;
    return sv;
  }
  if (value.is_number_integer()) {
    sv.type = T_NUMBER;
    sv.u.number = value.get<LPC_INT>();
    return sv;
  }
  if (value.is_number_unsigned()) {
    sv.type = T_NUMBER;
    sv.u.number = static_cast<LPC_INT>(value.get<std::uint64_t>());
    return sv;
  }
  if (value.is_number_float()) {
    sv.type = T_REAL;
    sv.u.real = value.get<LPC_FLOAT>();
    return sv;
  }

  sv.type = T_NUMBER;
  sv.u.number = 0;
  return sv;
}

bool gateway_svalue_to_json_impl(const svalue_t *sv, nlohmann::json *out, int depth) {
  if (!sv || !out || depth > kGatewayMaxJsonDepth) {
    return false;
  }

  switch (sv->type) {
    case T_NUMBER:
      *out = sv->u.number;
      return true;
    case T_REAL:
      *out = sv->u.real;
      return true;
    case T_STRING:
      *out = sv->u.string ? nlohmann::json(std::string(sv->u.string)) : nlohmann::json("");
      return true;
    case T_ARRAY: {
      nlohmann::json arr = nlohmann::json::array();
      for (int i = 0; i < sv->u.arr->size; i++) {
        nlohmann::json item;
        if (!gateway_svalue_to_json_impl(&sv->u.arr->item[i], &item, depth + 1)) {
          return false;
        }
        arr.push_back(item);
      }
      *out = std::move(arr);
      return true;
    }
    case T_MAPPING: {
      nlohmann::json obj = nlohmann::json::object();
      for (int i = 0; i < sv->u.map->table_size; i++) {
        for (auto *node = sv->u.map->table[i]; node; node = node->next) {
          if (node->values[0].type != T_STRING || !node->values[0].u.string) {
            return false;
          }
          nlohmann::json item;
          if (!gateway_svalue_to_json_impl(&node->values[1], &item, depth + 1)) {
            return false;
          }
          obj[std::string(node->values[0].u.string)] = std::move(item);
        }
      }
      *out = std::move(obj);
      return true;
    }
    case T_OBJECT:
      if (!sv->u.ob || (sv->u.ob->flags & O_DESTRUCTED)) {
        *out = nullptr;
        return true;
      }
      *out = std::string(sv->u.ob->obname);
      return true;
    default:
      *out = nullptr;
      return true;
  }
}

int gateway_svalue_to_json_string_impl(const svalue_t *sv, std::string *out) {
  nlohmann::json value;

  if (!out || !gateway_svalue_to_json_impl(sv, &value, 0)) {
    return 0;
  }
  *out = value.dump();
  return 1;
}

void gateway_send_json_to_fd(int fd, const nlohmann::json &payload) {
  auto encoded = payload.dump();
  gateway_send_raw_to_fd(fd, encoded.c_str(), encoded.size());
}

void gateway_remove_master(int fd);

void gateway_handle_heartbeat(int fd) {
  auto it = g_gateway_masters.find(fd);
  if (it == g_gateway_masters.end() || !it->second) {
    return;
  }
  it->second->last_active = get_current_time();
}

int next_gateway_fd() {
  while (g_gateway_masters.count(g_gateway_next_fd)) {
    g_gateway_next_fd++;
    if (g_gateway_next_fd <= 0) {
      g_gateway_next_fd = 1;
    }
  }
  return g_gateway_next_fd++;
}

void gateway_remove_master(int fd) {
  auto it = g_gateway_masters.find(fd);
  if (it == g_gateway_masters.end()) {
    return;
  }
  gateway_cleanup_master_sessions(fd);
  g_gateway_masters.erase(it);
}

void gateway_handle_hello(int fd, const nlohmann::json &msg) {
  if (g_gateway_debug) {
    debug_message("[gateway] hello fd=%d\n", fd);
  }
  gateway_handle_heartbeat(fd);
}

void gateway_handle_login(int fd, const nlohmann::json &msg) {
  std::string session_id;
  std::string ip;
  int port = 0;
  svalue_t data_sv = {};

  if (!msg.contains("cid") || !msg["cid"].is_string()) {
    return;
  }
  if (g_gateway_debug) {
    debug_message("[gateway] login fd=%d cid=%s\n", fd, msg["cid"].get_ref<const std::string &>().c_str());
  }
  session_id = msg["cid"].get<std::string>();
  if (session_id.empty()) {
    return;
  }
  if (msg.contains("data") && msg["data"].is_object()) {
    const auto &data = msg["data"];
    if (data.contains("ip") && data["ip"].is_string()) {
      ip = data["ip"].get<std::string>();
    }
    if (data.contains("port") && data["port"].is_number_integer()) {
      port = data["port"].get<int>();
    }
    data_sv = json_to_gateway_svalue(data);
  }

  gateway_create_session_internal(session_id.c_str(), msg.contains("data") ? &data_sv : nullptr,
                                  ip.c_str(), port, fd);
  if (msg.contains("data")) {
    free_svalue(&data_sv, "gateway_login_data");
  }
}

void gateway_handle_data(int fd, const nlohmann::json &msg) {
  std::string session_id;
  GatewaySession *sess = nullptr;
  object_t *user = nullptr;
  svalue_t data_sv = {};

  if (!msg.contains("cid") || !msg["cid"].is_string() || !msg.contains("data")) {
    return;
  }
  if (g_gateway_debug) {
    debug_message("[gateway] data fd=%d cid=%s\n", fd, msg["cid"].get_ref<const std::string &>().c_str());
  }
  session_id = msg["cid"].get<std::string>();
  if (session_id.empty()) {
    return;
  }
  sess = gateway_find_session(session_id.c_str());
  user = sess ? sess->user_ob : nullptr;
  if (!gateway_object_valid_local(user)) {
    return;
  }
  sess->last_active = get_current_time();
  if (user->interactive) {
    user->interactive->last_time = sess->last_active;
  }
  data_sv = json_to_gateway_svalue(msg["data"]);
  gateway_apply_receive(user, &data_sv);
  free_svalue(&data_sv, "gateway_data");
}

void gateway_handle_discon(int fd, const nlohmann::json &msg) {
  std::string reason_code = "client_disconnected";
  std::string reason_text = "client disconnect";

  if (!msg.contains("cid") || !msg["cid"].is_string()) {
    return;
  }
  if (g_gateway_debug) {
    debug_message("[gateway] discon fd=%d cid=%s\n", fd, msg["cid"].get_ref<const std::string &>().c_str());
  }
  if (msg.contains("reason_code") && msg["reason_code"].is_string() &&
      !msg["reason_code"].get_ref<const std::string &>().empty()) {
    reason_code = msg["reason_code"].get<std::string>();
  }
  if (msg.contains("reason_text") && msg["reason_text"].is_string() &&
      !msg["reason_text"].get_ref<const std::string &>().empty()) {
    reason_text = msg["reason_text"].get<std::string>();
  } else if (msg.contains("reason") && msg["reason"].is_string() &&
             !msg["reason"].get_ref<const std::string &>().empty()) {
    reason_text = msg["reason"].get<std::string>();
  }
  gateway_destroy_session_internal(msg["cid"].get_ref<const std::string &>().c_str(),
                                   reason_code.c_str(), reason_text.c_str());
}

void gateway_handle_sys(int fd, const nlohmann::json &msg) {
  std::string action;

  gateway_handle_heartbeat(fd);
  if (!msg.contains("action") || !msg["action"].is_string()) {
    return;
  }

  action = msg["action"].get<std::string>();
  if (g_gateway_debug) {
    debug_message("[gateway] sys fd=%d action=%s\n", fd, action.c_str());
  }

  if (action == "ping") {
    nlohmann::json response = {
        {"type", "sys"},
        {"action", "pong"},
    };
    if (msg.contains("ts")) {
      response["ts"] = msg["ts"];
    }
    gateway_send_json_to_fd(fd, response);
    return;
  }

  if (action == "pong") {
    return;
  }

  if (msg.contains("cid") && msg["cid"].is_string()) {
    auto session_id = msg["cid"].get<std::string>();
    auto *sess = gateway_find_session(session_id.c_str());
    auto *user = sess ? sess->user_ob : nullptr;
    if (gateway_object_valid_local(user)) {
      svalue_t data_sv = {};
      sess->last_active = get_current_time();
      if (user->interactive) {
        user->interactive->last_time = sess->last_active;
      }
      if (msg.contains("data")) {
        data_sv = json_to_gateway_svalue(msg["data"]);
      } else {
        data_sv.type = T_NUMBER;
        data_sv.u.number = 0;
      }
      gateway_apply_receive(user, &data_sv);
      free_svalue(&data_sv, "gateway_sys_data");
      return;
    }
  }

  if (auto *gateway_d = find_object("/adm/daemons/gateway_d")) {
    svalue_t msg_sv = json_to_gateway_svalue(msg);
    save_command_giver(gateway_d);
    set_eval(max_eval_cost);
    push_svalue(&msg_sv);
    safe_apply("receive_system_message", gateway_d, 1, ORIGIN_DRIVER);
    restore_command_giver();
    free_svalue(&msg_sv, "gateway_sys_msg");
  }
}

void gateway_dispatch_message(int fd, const nlohmann::json &msg) {
  std::string type;

  if (!msg.is_object() || !msg.contains("type") || !msg["type"].is_string()) {
    return;
  }
  type = msg["type"].get<std::string>();
  if (type == "hello") {
    gateway_handle_hello(fd, msg);
    return;
  }
  if (type == "login") {
    gateway_handle_login(fd, msg);
    return;
  }
  if (type == "data") {
    gateway_handle_data(fd, msg);
    return;
  }
  if (type == "discon") {
    gateway_handle_discon(fd, msg);
    return;
  }
  if (type == "sys") {
    gateway_handle_sys(fd, msg);
    return;
  }
}

void gateway_eventcb(bufferevent * /*bev*/, short events, void *ctx) {
  auto *master = reinterpret_cast<GatewayMaster *>(ctx);
  if (!master) {
    return;
  }
  if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR | BEV_EVENT_TIMEOUT)) {
    gateway_remove_master(master->fd);
  }
}

void gateway_heartbeat_timer_cb(evutil_socket_t /*fd*/, short /*what*/, void * /*ctx*/) {
  gateway_check_heartbeat_timeouts();
  gateway_check_session_timeouts();
  if (g_gateway_heartbeat_timer && g_gateway_heartbeat_interval > 0) {
    timeval tv = {g_gateway_heartbeat_interval, 0};
    evtimer_add(g_gateway_heartbeat_timer, &tv);
  }
}

int gateway_start_heartbeat_timer() {
  gateway_stop_heartbeat_timer();
  if (!g_event_base || g_gateway_heartbeat_interval <= 0) {
    return 0;
  }

  g_gateway_heartbeat_timer = evtimer_new(g_event_base, gateway_heartbeat_timer_cb, nullptr);
  if (!g_gateway_heartbeat_timer) {
    return 0;
  }

  timeval tv = {g_gateway_heartbeat_interval, 0};
  evtimer_add(g_gateway_heartbeat_timer, &tv);
  return 1;
}

void gateway_stop_heartbeat_timer() {
  if (!g_gateway_heartbeat_timer) {
    return;
  }

  evtimer_del(g_gateway_heartbeat_timer);
  event_free(g_gateway_heartbeat_timer);
  g_gateway_heartbeat_timer = nullptr;
}

void gateway_readcb(bufferevent *bev, void *ctx) {
  auto *master = reinterpret_cast<GatewayMaster *>(ctx);
  auto *input = static_cast<evbuffer *>(nullptr);
  size_t len;
  std::string chunk;

  if (!master || !bev) {
    return;
  }

  input = bufferevent_get_input(bev);
  if (!input) {
    return;
  }

  len = evbuffer_get_length(input);
  if (len == 0) {
    return;
  }

  chunk.resize(len);
  if (evbuffer_remove(input, chunk.data(), len) <= 0) {
    return;
  }
  master->last_active = get_current_time();
  master->read_buffer += chunk;

  while (master->read_buffer.size() >= sizeof(uint32_t)) {
    uint32_t frame_len;

    memcpy(&frame_len, master->read_buffer.data(), sizeof(frame_len));
    frame_len = ntohl(frame_len);
    if (frame_len == 0 || frame_len > 16 * 1024 * 1024) {
      gateway_remove_master(master->fd);
      return;
    }
    if (master->read_buffer.size() < sizeof(uint32_t) + frame_len) {
      break;
    }

    auto payload = master->read_buffer.substr(sizeof(uint32_t), frame_len);
    master->read_buffer.erase(0, sizeof(uint32_t) + frame_len);
    try {
      auto msg = nlohmann::json::parse(payload);
      gateway_dispatch_message(master->fd, msg);
      master->messages_received++;
    } catch (...) {
      continue;
    }
  }
}

void gateway_listener_cb(evconnlistener *listener, evutil_socket_t fd,
                         sockaddr *sa, int socklen, void * /*ctx*/) {
  char ipbuf[INET6_ADDRSTRLEN] = {0};
  if (g_gateway_max_masters > 0 && static_cast<int>(g_gateway_masters.size()) >= g_gateway_max_masters) {
    evutil_closesocket(fd);
    return;
  }

  auto *base = evconnlistener_get_base(listener);
  auto bev = bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE);
  if (!bev) {
    evutil_closesocket(fd);
    return;
  }

  if (sa && sa->sa_family == AF_INET) {
    evutil_inet_ntop(AF_INET, &reinterpret_cast<sockaddr_in *>(sa)->sin_addr, ipbuf,
                     sizeof(ipbuf));
  } else if (sa && sa->sa_family == AF_INET6) {
    evutil_inet_ntop(AF_INET6, &reinterpret_cast<sockaddr_in6 *>(sa)->sin6_addr, ipbuf,
                     sizeof(ipbuf));
  }

  auto master = std::make_unique<GatewayMaster>();
  master->fd = next_gateway_fd();
  master->bev = bev;
  master->ip = ipbuf;
  master->connected_at = get_current_time();
  master->last_active = master->connected_at;

  bufferevent_setcb(bev, gateway_readcb, nullptr, gateway_eventcb, master.get());
  bufferevent_enable(bev, EV_READ | EV_WRITE);
  g_gateway_masters[master->fd] = std::move(master);
}

void gateway_listener_error_cb(evconnlistener * /*listener*/, void * /*ctx*/) {
  debug_message("Gateway listener error.\n");
}
}  // namespace

int gateway_svalue_to_json_string(const svalue_t *sv, std::string *out) {
  return gateway_svalue_to_json_string_impl(sv, out);
}

GatewayMaster::~GatewayMaster() {
  if (bev) {
    bufferevent_free(bev);
    bev = nullptr;
  }
}

void init_gateway(void) {
  g_gateway_debug = CONFIG_INT(__RC_GATEWAY_DEBUG__) ? 1 : 0;
  g_gateway_max_packet_size = CONFIG_INT(__RC_GATEWAY_PACKET_SIZE__) > 0
                                  ? static_cast<size_t>(CONFIG_INT(__RC_GATEWAY_PACKET_SIZE__))
                                  : static_cast<size_t>(1024 * 1024);
  g_gateway_max_masters = kGatewayDefaultMaxMasters;
  g_gateway_max_sessions = g_gateway_max_sessions > 0 ? g_gateway_max_sessions : 4096;
  g_gateway_heartbeat_interval = kGatewayDefaultHeartbeatInterval;
  g_gateway_heartbeat_timeout = kGatewayDefaultHeartbeatTimeout;
  if (!g_gateway_started_at) {
    g_gateway_started_at = get_current_time();
  }
  debug_message("Gateway config: port=%d external=%d debug=%d packet_size=%d\n",
                CONFIG_INT(__RC_GATEWAY_PORT__), CONFIG_INT(__RC_GATEWAY_EXTERNAL__),
                g_gateway_debug, CONFIG_INT(__RC_GATEWAY_PACKET_SIZE__));
  if (g_gateway_debug) {
    debug_message("Gateway debug mode enabled.\n");
  }
  if (CONFIG_INT(__RC_GATEWAY_PORT__) > 0) {
    gateway_listen_internal(CONFIG_INT(__RC_GATEWAY_PORT__), CONFIG_INT(__RC_GATEWAY_EXTERNAL__));
  }
  gateway_start_heartbeat_timer();
  debug_message("Gateway package initialized.\n");
}

void cleanup_gateway(void) {
  gateway_stop_heartbeat_timer();
  cleanup_gateway_sessions();
  g_gateway_masters.clear();
  if (g_gateway_listener) {
    evconnlistener_free(g_gateway_listener);
    g_gateway_listener = nullptr;
  }
  g_gateway_listen_port = 0;
}

int gateway_listen_internal(int port, int bind_all) {
  sockaddr_in sin{};

  if (port <= 0 || port > 65535 || !g_event_base) {
    debug_message("Gateway listen skipped: invalid port or missing event base.\n");
    return 0;
  }

  if (g_gateway_listener) {
    evconnlistener_free(g_gateway_listener);
    g_gateway_listener = nullptr;
  }

  sin.sin_family = AF_INET;
  sin.sin_port = htons(port);
  sin.sin_addr.s_addr = bind_all ? htonl(INADDR_ANY) : htonl(INADDR_LOOPBACK);

  g_gateway_listener = evconnlistener_new_bind(
      g_event_base, gateway_listener_cb, nullptr,
      LEV_OPT_REUSEABLE | LEV_OPT_CLOSE_ON_FREE, -1,
      reinterpret_cast<sockaddr *>(&sin), sizeof(sin));
  if (!g_gateway_listener) {
    g_gateway_listen_port = 0;
    debug_message("Gateway listener failed to bind on %s:%d\n",
                  bind_all ? "0.0.0.0" : "127.0.0.1", port);
    return 0;
  }

  evconnlistener_set_error_cb(g_gateway_listener, gateway_listener_error_cb);
  g_gateway_listen_port = port;
  debug_message("Accepting [Gateway] connections on %s:%d\n",
                bind_all ? "0.0.0.0" : "127.0.0.1", port);
  return 1;
}

int gateway_send_raw_to_fd(int fd, const char *data, size_t len) {
  auto it = g_gateway_masters.find(fd);
  uint32_t net_len;
  auto *output = static_cast<evbuffer *>(nullptr);

  if (!data || len == 0 || len > g_gateway_max_packet_size || it == g_gateway_masters.end()) {
    return 0;
  }
  if (!it->second || !it->second->bev || it->second->closing) {
    return 0;
  }

  output = bufferevent_get_output(it->second->bev);
  if (!output) {
    return 0;
  }

  net_len = htonl(static_cast<uint32_t>(len));
  if (evbuffer_add(output, &net_len, sizeof(net_len)) != 0) {
    return 0;
  }
  if (evbuffer_add(output, data, len) != 0) {
    return 0;
  }

  it->second->messages_sent++;
  it->second->last_active = get_current_time();

  return 1;
}

int gateway_ping_master_internal(int fd) {
  static const char *ping_msg = "{\"type\":\"sys\",\"action\":\"ping\"}";
  return gateway_send_raw_to_fd(fd, ping_msg, strlen(ping_msg));
}

bool gateway_has_master(int fd) {
  return g_gateway_masters.find(fd) != g_gateway_masters.end();
}

void gateway_check_heartbeat_timeouts() {
  std::vector<int> to_remove;
  time_t now = get_current_time();

  if (g_gateway_heartbeat_timeout <= 0) {
    return;
  }

  for (const auto &entry : g_gateway_masters) {
    if (!entry.second) {
      continue;
    }
    if ((now - entry.second->last_active) > g_gateway_heartbeat_timeout) {
      to_remove.push_back(entry.first);
    }
  }

  for (int fd : to_remove) {
    if (g_gateway_debug) {
      debug_message("[gateway] heartbeat timeout fd=%d\n", fd);
    }
    gateway_remove_master(fd);
  }
}

mapping_t *gateway_status_internal() {
  mapping_t *map;
  int uptime;

  uptime = g_gateway_started_at ? static_cast<int>(get_current_time() - g_gateway_started_at) : 0;
  map = allocate_mapping(12);
  add_mapping_pair(map, "listening", g_gateway_listener ? 1 : 0);
  add_mapping_pair(map, "port", g_gateway_listen_port);
  add_mapping_pair(map, "masters", static_cast<int>(g_gateway_masters.size()));
  add_mapping_pair(map, "sessions", gateway_get_session_count());
  add_mapping_pair(map, "debug", g_gateway_debug);
  add_mapping_pair(map, "max_packet_size", static_cast<LPC_INT>(g_gateway_max_packet_size));
  add_mapping_pair(map, "max_masters", g_gateway_max_masters);
  add_mapping_pair(map, "max_sessions", g_gateway_max_sessions);
  add_mapping_pair(map, "heartbeat_interval", g_gateway_heartbeat_interval);
  add_mapping_pair(map, "heartbeat_timeout", g_gateway_heartbeat_timeout);
  add_mapping_string(map, "heartbeat_timer", g_gateway_heartbeat_timer ? "active" : "inactive");
  add_mapping_pair(map, "uptime", uptime);
  return map;
}

void f_is_gateway_user() {
  auto *ob = sp->u.ob;

  if (sp->type != T_OBJECT || !ob || (ob->flags & O_DESTRUCTED)) {
    if (sp->type == T_OBJECT) {
      free_object(&sp->u.ob, "f_is_gateway_user");
    }
    put_number(0);
    return;
  }

  free_object(&sp->u.ob, "f_is_gateway_user");
  put_number(gateway_is_session(ob) ? 1 : 0);
}

void f_gateway_listen() {
  int bind_all = 0;
  int port = 0;

  if (st_num_arg > 1 && sp->type == T_NUMBER) {
    bind_all = sp->u.number;
    pop_stack();
  }
  if (sp->type == T_NUMBER) {
    port = sp->u.number;
  }
  pop_stack();
  put_number(gateway_listen_internal(port, bind_all));
}

void f_gateway_status() {
  auto *map = gateway_status_internal();
  push_refed_mapping(map);
}

void f_gateway_config() {
  int num_args = st_num_arg;
  const char *key = (num_args >= 1 && (sp - num_args + 1)->type == T_STRING)
                        ? (sp - num_args + 1)->u.string
                        : nullptr;
  svalue_t *val = num_args >= 2 ? (sp - num_args + 2) : nullptr;

  if (!key) {
    pop_n_elems(num_args);
    push_number(0);
    return;
  }

  if (strcmp(key, "max_sessions") == 0) {
    if (val && val->type == T_NUMBER && val->u.number > 0) {
      g_gateway_max_sessions = val->u.number;
    }
    pop_n_elems(num_args);
    push_number(g_gateway_max_sessions);
    return;
  }
  if (strcmp(key, "max_masters") == 0) {
    if (val && val->type == T_NUMBER && val->u.number > 0) {
      g_gateway_max_masters = val->u.number;
    }
    pop_n_elems(num_args);
    push_number(g_gateway_max_masters);
    return;
  }
  if (strcmp(key, "timeout") == 0 || strcmp(key, "heartbeat_timeout") == 0) {
    if (val && val->type == T_NUMBER && val->u.number > 0) {
      g_gateway_heartbeat_timeout = val->u.number;
    }
    pop_n_elems(num_args);
    push_number(g_gateway_heartbeat_timeout);
    return;
  }
  if (strcmp(key, "heartbeat_interval") == 0) {
    if (val && val->type == T_NUMBER && val->u.number > 0) {
      g_gateway_heartbeat_interval = val->u.number;
      gateway_start_heartbeat_timer();
    }
    pop_n_elems(num_args);
    push_number(g_gateway_heartbeat_interval);
    return;
  }
  if (strcmp(key, "debug") == 0) {
    if (val && val->type == T_NUMBER) {
      g_gateway_debug = val->u.number ? 1 : 0;
    }
    pop_n_elems(num_args);
    push_number(g_gateway_debug);
    return;
  }
  if (strcmp(key, "max_packet_size") == 0) {
    if (val && val->type == T_NUMBER && val->u.number >= 1024) {
      g_gateway_max_packet_size = static_cast<size_t>(val->u.number);
    }
    pop_n_elems(num_args);
    push_number(static_cast<LPC_INT>(g_gateway_max_packet_size));
    return;
  }

  pop_n_elems(num_args);
  push_number(0);
}

void f_gateway_set_heartbeat() {
  int num_args = st_num_arg;
  int interval = (num_args >= 1 && (sp - num_args + 1)->type == T_NUMBER)
                     ? (sp - num_args + 1)->u.number
                     : g_gateway_heartbeat_interval;
  int timeout = (num_args >= 2 && (sp - num_args + 2)->type == T_NUMBER)
                    ? (sp - num_args + 2)->u.number
                    : g_gateway_heartbeat_timeout;

  pop_n_elems(num_args);
  if (interval > 0) {
    g_gateway_heartbeat_interval = interval;
  }
  if (timeout > 0) {
    g_gateway_heartbeat_timeout = timeout;
  }
  gateway_start_heartbeat_timer();
  push_number(1);
}

void f_gateway_check_timeout() {
  if (st_num_arg > 0) {
    pop_n_elems(st_num_arg);
  }
  gateway_check_heartbeat_timeouts();
  gateway_check_session_timeouts();
  push_number(1);
}

void f_gateway_ping_master() {
  int num_args = st_num_arg;
  int master_fd = (num_args >= 1 && (sp - num_args + 1)->type == T_NUMBER)
                      ? (sp - num_args + 1)->u.number
                      : 0;
  int result = 0;

  if (num_args > 0) {
    pop_n_elems(num_args);
  }

  if (master_fd > 0) {
    result = gateway_ping_master_internal(master_fd);
  } else {
    for (const auto &entry : g_gateway_masters) {
      result += gateway_ping_master_internal(entry.first);
    }
  }

  push_number(result);
}

void f_gateway_send() {
  int num_args = st_num_arg;
  svalue_t *data_sv = num_args >= 1 ? (sp - num_args + 1) : nullptr;
  int master_fd = (num_args >= 2 && (sp - num_args + 2)->type == T_NUMBER)
                      ? (sp - num_args + 2)->u.number
                      : 0;
  std::string encoded;
  int sent = 0;

  if (!data_sv || !gateway_svalue_to_json_string(data_sv, &encoded)) {
    pop_n_elems(num_args);
    push_number(0);
    return;
  }

  pop_n_elems(num_args);
  if (master_fd > 0) {
    sent = gateway_send_raw_to_fd(master_fd, encoded.c_str(), encoded.size());
    push_number(sent);
    return;
  }

  for (const auto &entry : g_gateway_masters) {
    sent += gateway_send_raw_to_fd(entry.first, encoded.c_str(), encoded.size());
  }
  push_number(sent);
}
