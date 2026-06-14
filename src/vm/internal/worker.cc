#include "vm/worker.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <future>
#include <limits>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include "base/internal/tracing.h"

namespace {

struct AsyncRecord {
  VMWorkerTaskState state{VMWorkerTaskState::kPending};
  std::string type;
  VMWorkerTaskEnvelope envelope;
  VMWorkerBenchResult bench;
  VMWorkerSnapshotDigestResult snapshot_digest;
  VMWorkerActorScoreResult actor_score;
  VMWorkerCombatDamageResult combat_damage;
  std::string error;
};

struct AsyncBenchmarkState {
  uint64_t task_id{0};
  int tasks{0};
  int worker_count{0};
  std::chrono::steady_clock::time_point started;
  std::shared_ptr<std::atomic<bool>> start_barrier;
  std::shared_ptr<std::atomic<int>> active;
  std::shared_ptr<std::atomic<int>> max_parallel;
  std::shared_ptr<std::atomic<int>> remaining;
  std::shared_ptr<std::atomic<uint64_t>> checksum;
};

void update_max(std::atomic<int> &target, int value) {
  auto current = target.load();
  while (value > current && !target.compare_exchange_weak(current, value)) {
  }
}

uint64_t now_ms() {
  return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
      std::chrono::steady_clock::now().time_since_epoch()).count());
}

uint64_t hash_mix(uint64_t current, uint64_t value) {
  current ^= value + 0x9e3779b97f4a7c15ULL + (current << 6) + (current >> 2);
  return current;
}

uint64_t hash_string(uint64_t current, const std::string &value) {
  for (auto ch : value) {
    current ^= static_cast<unsigned char>(ch);
    current *= 1099511628211ULL;
  }
  return current;
}

int normalize_timeout_ms(int timeout_ms) {
  if (timeout_ms <= 0) {
    return 0;
  }
  return std::clamp(timeout_ms, 1, 600000);
}

int normalize_ttl_ms(int ttl_ms) { return std::clamp(ttl_ms, 0, 600000); }

int ratio_bp(int value, int max_value) {
  if (max_value <= 0 || value <= 0) {
    return 0;
  }
  value = std::min(value, max_value);
  return static_cast<int>((static_cast<int64_t>(value) * 10000) / max_value);
}

std::string actor_state_from_score(int total_score);

int clamp_int(int value, int min_value, int max_value) {
  return std::clamp(value, min_value, max_value);
}

int clamp_i64_to_int(int64_t value, int min_value, int max_value) {
  if (value < min_value) {
    return min_value;
  }
  if (value > max_value) {
    return max_value;
  }
  return static_cast<int>(value);
}

int64_t safe_denominator(int64_t value) { return value < 1 ? 1 : value; }

void normalize_min_max(int *min_value, int *max_value) {
  if (*min_value > *max_value) {
    std::swap(*min_value, *max_value);
  }
}

VMWorkerCombatDamageInput normalize_combat_damage_input(VMWorkerCombatDamageInput input) {
  constexpr int kBpBase = 10000;
  constexpr int kStatMax = 1000000000;
  constexpr int kFactorMax = 100000;

  input.snapshot_hash = clamp_int(input.snapshot_hash, 0, std::numeric_limits<int>::max());
  input.attack = clamp_int(input.attack, 1, kStatMax);
  input.defense = clamp_int(input.defense, 0, kStatMax);
  input.armor_break = clamp_int(input.armor_break, 0, kStatMax);
  input.critical = clamp_int(input.critical, 0, kStatMax);
  input.critical_resist = clamp_int(input.critical_resist, 0, kStatMax);
  input.armor_break_defense_factor_bp = clamp_int(input.armor_break_defense_factor_bp, 0, kFactorMax);
  input.armor_break_flat = clamp_int(input.armor_break_flat, 0, kStatMax);
  input.armor_break_cap_bp = clamp_int(input.armor_break_cap_bp, 0, kBpBase);
  input.reduction_attack_factor_bp = clamp_int(input.reduction_attack_factor_bp, 0, kFactorMax);
  input.reduction_flat = clamp_int(input.reduction_flat, 0, kStatMax);
  input.reduction_min_bp = clamp_int(input.reduction_min_bp, 0, kBpBase);
  input.reduction_max_bp = clamp_int(input.reduction_max_bp, 0, kBpBase);
  normalize_min_max(&input.reduction_min_bp, &input.reduction_max_bp);
  input.damage_base = clamp_int(input.damage_base, 0, kStatMax);
  input.damage_skill_factor_bp = clamp_int(input.damage_skill_factor_bp, 0, kFactorMax);
  input.damage_random_min_bp = clamp_int(input.damage_random_min_bp, 0, kFactorMax);
  input.damage_random_max_bp = clamp_int(input.damage_random_max_bp, 0, kFactorMax);
  normalize_min_max(&input.damage_random_min_bp, &input.damage_random_max_bp);
  input.damage_min = clamp_int(input.damage_min, 0, kStatMax);
  input.variance_roll_bp = clamp_int(input.variance_roll_bp, 0,
                                     input.damage_random_max_bp - input.damage_random_min_bp);
  input.critical_base_bp = clamp_int(input.critical_base_bp, 0, kFactorMax);
  input.critical_swing_bp = clamp_int(input.critical_swing_bp, 0, kFactorMax);
  input.critical_flat = clamp_int(input.critical_flat, 0, kStatMax);
  input.critical_min = clamp_int(input.critical_min, 0, 100);
  input.critical_max = clamp_int(input.critical_max, 0, 100);
  normalize_min_max(&input.critical_min, &input.critical_max);
  input.critical_roll = clamp_int(input.critical_roll, 0, 99);
  input.critical_damage_factor_bp = clamp_int(input.critical_damage_factor_bp, 0, kFactorMax);
  return input;
}

uint64_t hash_combat_damage_input(VMWorkerCombatDamageInput input) {
  input = normalize_combat_damage_input(input);
  uint64_t hash = 1469598103934665603ULL;
  hash = hash_mix(hash, static_cast<uint64_t>(input.snapshot_hash));
  hash = hash_mix(hash, static_cast<uint64_t>(input.attack));
  hash = hash_mix(hash, static_cast<uint64_t>(input.defense));
  hash = hash_mix(hash, static_cast<uint64_t>(input.armor_break));
  hash = hash_mix(hash, static_cast<uint64_t>(input.critical));
  hash = hash_mix(hash, static_cast<uint64_t>(input.critical_resist));
  hash = hash_mix(hash, static_cast<uint64_t>(input.armor_break_defense_factor_bp));
  hash = hash_mix(hash, static_cast<uint64_t>(input.armor_break_flat));
  hash = hash_mix(hash, static_cast<uint64_t>(input.armor_break_cap_bp));
  hash = hash_mix(hash, static_cast<uint64_t>(input.reduction_attack_factor_bp));
  hash = hash_mix(hash, static_cast<uint64_t>(input.reduction_flat));
  hash = hash_mix(hash, static_cast<uint64_t>(input.reduction_min_bp));
  hash = hash_mix(hash, static_cast<uint64_t>(input.reduction_max_bp));
  hash = hash_mix(hash, static_cast<uint64_t>(input.damage_base));
  hash = hash_mix(hash, static_cast<uint64_t>(input.damage_skill_factor_bp));
  hash = hash_mix(hash, static_cast<uint64_t>(input.damage_random_min_bp));
  hash = hash_mix(hash, static_cast<uint64_t>(input.damage_random_max_bp));
  hash = hash_mix(hash, static_cast<uint64_t>(input.damage_min));
  hash = hash_mix(hash, static_cast<uint64_t>(input.variance_roll_bp));
  hash = hash_mix(hash, static_cast<uint64_t>(input.critical_base_bp));
  hash = hash_mix(hash, static_cast<uint64_t>(input.critical_swing_bp));
  hash = hash_mix(hash, static_cast<uint64_t>(input.critical_flat));
  hash = hash_mix(hash, static_cast<uint64_t>(input.critical_min));
  hash = hash_mix(hash, static_cast<uint64_t>(input.critical_max));
  hash = hash_mix(hash, static_cast<uint64_t>(input.critical_roll));
  hash = hash_mix(hash, static_cast<uint64_t>(input.critical_damage_factor_bp));
  return hash;
}

void fill_combat_damage_result(VMWorkerCombatDamageResult *result,
                               const VMWorkerCombatDamageInput &input) {
  constexpr int kBpBase = 10000;
  auto normalized = normalize_combat_damage_input(input);
  int64_t attack = normalized.attack;
  int64_t defense = normalized.defense;
  int64_t armor_break = normalized.armor_break;
  int64_t denominator = safe_denominator(
      armor_break + defense * normalized.armor_break_defense_factor_bp / kBpBase + normalized.armor_break_flat);
  int armor_break_bp = clamp_i64_to_int(armor_break * kBpBase / denominator, 0,
                                        normalized.armor_break_cap_bp);
  int64_t effective_defense = defense * (kBpBase - armor_break_bp) / kBpBase;
  denominator = safe_denominator(effective_defense + attack * normalized.reduction_attack_factor_bp / kBpBase +
                                 normalized.reduction_flat);
  int reduction_bp = clamp_i64_to_int(effective_defense * kBpBase / denominator,
                                      normalized.reduction_min_bp, normalized.reduction_max_bp);

  int64_t damage = normalized.damage_base + attack * normalized.damage_skill_factor_bp / kBpBase;
  int variance = normalized.damage_random_max_bp - normalized.damage_random_min_bp;
  if (variance > 0) {
    damage = damage * (normalized.damage_random_min_bp + normalized.variance_roll_bp) / kBpBase;
  }
  damage = damage * (kBpBase - reduction_bp) / kBpBase;

  int64_t crit_denominator = safe_denominator(static_cast<int64_t>(normalized.critical) +
                                              normalized.critical_resist + normalized.critical_flat);
  int critical_rate = clamp_i64_to_int(
      (normalized.critical_base_bp + normalized.critical_swing_bp *
          (static_cast<int64_t>(normalized.critical) - normalized.critical_resist) / crit_denominator) / 100,
      normalized.critical_min, normalized.critical_max);
  int critical_hit = critical_rate > normalized.critical_roll ? 1 : 0;
  if (critical_hit) {
    damage = damage * normalized.critical_damage_factor_bp / kBpBase;
  }
  if (damage < normalized.damage_min) {
    damage = normalized.damage_min;
  }

  result->damage = clamp_i64_to_int(damage, 0, std::numeric_limits<int>::max());
  result->armor_break_bp = armor_break_bp;
  result->reduction_bp = reduction_bp;
  result->critical_rate = critical_rate;
  result->critical_hit = critical_hit;
  result->snapshot_hash = static_cast<uint64_t>(normalized.snapshot_hash);
  result->input_hash = hash_combat_damage_input(normalized);
}

void fill_actor_score_result(VMWorkerActorScoreResult *result,
                             const VMWorkerActorScoreInput &input) {
  result->hp_pct_bp = ratio_bp(input.hp, input.max_hp);
  result->mp_pct_bp = ratio_bp(input.mp, input.max_mp);
  result->ep_pct_bp = ratio_bp(input.ep, input.max_ep);
  result->survival_score = result->hp_pct_bp;
  result->resource_score = (result->mp_pct_bp + result->ep_pct_bp) / 2;
  result->total_score = (result->survival_score * 7 + result->resource_score * 3) / 10;
  result->state = actor_state_from_score(result->total_score);
}

std::string actor_state_from_score(int total_score) {
  if (total_score >= 8000) {
    return "stable";
  }
  if (total_score >= 5000) {
    return "strained";
  }
  if (total_score > 0) {
    return "critical";
  }
  return "down";
}

class VMWorkerRuntime {
 public:
  ~VMWorkerRuntime() { stop(); }

  void start(int requested_workers) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!workers_.empty()) {
      return;
    }
    stopping_ = false;
    auto detected = static_cast<int>(std::thread::hardware_concurrency());
    auto count = requested_workers > 0 ? requested_workers : std::max(1, detected - 1);
    count = std::clamp(count, 1, 64);
    for (int i = 0; i < count; i++) {
      workers_.emplace_back([this] { run(); });
    }
  }

  void stop() {
    std::vector<std::thread> workers;
    {
      std::lock_guard<std::mutex> lock(mutex_);
      stopping_ = true;
      workers.swap(workers_);
    }
    cv_.notify_all();
    for (auto &worker : workers) {
      if (worker.joinable()) {
        worker.join();
      }
    }
  }

  std::future<void> submit(std::function<void()> task) {
    auto promise = std::make_shared<std::promise<void>>();
    auto future = promise->get_future();
    auto accepted = false;
    {
      std::lock_guard<std::mutex> lock(mutex_);
      if (!stopping_) {
        accepted = true;
        submitted_++;
        tasks_.push_back(wrap_task(std::move(task), promise));
        update_queue_high_watermark(tasks_.size());
      }
    }
    if (!accepted) {
      try {
        throw std::runtime_error("VM worker runtime is stopping");
      } catch (...) {
        promise->set_exception(std::current_exception());
      }
      return future;
    }
    cv_.notify_one();
    return future;
  }

  std::future<void> submit_keyed(std::string owner_key, std::function<void()> task) {
    if (owner_key.empty()) {
      return submit(std::move(task));
    }

    auto promise = std::make_shared<std::promise<void>>();
    auto future = promise->get_future();
    auto accepted = false;
    auto wrapped = wrap_task(std::move(task), promise, owner_key);
    {
      std::lock_guard<std::mutex> lock(mutex_);
      if (!stopping_) {
        accepted = true;
        submitted_++;
        if (running_owner_keys_.count(owner_key) == 0) {
          running_owner_keys_.insert(owner_key);
          tasks_.push_back(std::move(wrapped));
          update_queue_high_watermark(tasks_.size());
        } else {
          owner_queues_[owner_key].push_back(std::move(wrapped));
        }
      }
    }
    if (!accepted) {
      try {
        throw std::runtime_error("VM worker runtime is stopping");
      } catch (...) {
        promise->set_exception(std::current_exception());
      }
      return future;
    }
    cv_.notify_one();
    return future;
  }

  VMWorkerStats stats() const {
    VMWorkerStats stats;
    {
      std::lock_guard<std::mutex> lock(mutex_);
      stats.worker_count = static_cast<int>(workers_.size());
      stats.submitted = submitted_.load();
      stats.completed = completed_.load();
      stats.queue_depth = tasks_.size();
      stats.queue_high_watermark = queue_high_watermark_.load();
      stats.owner_queue_depth = owner_queue_depth_locked();
      stats.active_owners = static_cast<int>(running_owner_keys_.size());
      stats.active = active_.load();
    }
    {
      std::lock_guard<std::mutex> lock(results_mutex_);
      for (const auto &entry : async_results_) {
        switch (entry.second.state) {
          case VMWorkerTaskState::kPending:
            stats.async_pending++;
            break;
          case VMWorkerTaskState::kSucceeded:
            stats.async_ready++;
            break;
          case VMWorkerTaskState::kFailed:
            stats.async_failed++;
            break;
          case VMWorkerTaskState::kUnknown:
            break;
        }
      }
    }
    return stats;
  }

  VMWorkerActorBenchResult actor_benchmark(int owners, int tasks_per_owner, int millis) {
    owners = std::clamp(owners, 1, 64);
    tasks_per_owner = std::clamp(tasks_per_owner, 1, 64);
    millis = std::clamp(millis, 1, 5000);
    start(0);

    auto stats = this->stats();
    auto total_tasks = owners * tasks_per_owner;
    auto start_barrier = std::make_shared<std::atomic<bool>>(false);
    auto active = std::make_shared<std::atomic<int>>(0);
    auto max_parallel = std::make_shared<std::atomic<int>>(0);
    auto checksum = std::make_shared<std::atomic<uint64_t>>(0);
    auto owner_active = std::make_shared<std::vector<std::atomic<int>>>(owners);
    auto max_owner_parallel = std::make_shared<std::atomic<int>>(0);
    std::vector<std::future<void>> futures;
    futures.reserve(total_tasks);

    auto start_time = std::chrono::steady_clock::now();
    for (int owner = 0; owner < owners; owner++) {
      for (int index = 0; index < tasks_per_owner; index++) {
        auto owner_key = std::string("actor/") + std::to_string(owner);
        futures.push_back(submit_keyed(owner_key, [=] {
          while (!start_barrier->load(std::memory_order_acquire)) {
            std::this_thread::yield();
          }
          auto running = active->fetch_add(1) + 1;
          update_max(*max_parallel, running);
          auto same_owner_running = (*owner_active)[owner].fetch_add(1) + 1;
          update_max(*max_owner_parallel, same_owner_running);
          auto end = std::chrono::steady_clock::now() + std::chrono::milliseconds(millis);
          uint64_t local = static_cast<uint64_t>((owner + 1) * 1000 + index + 1);
          while (std::chrono::steady_clock::now() < end) {
            local = local * 2862933555777941757ULL + 3037000493ULL;
          }
          checksum->fetch_add(local);
          (*owner_active)[owner].fetch_sub(1);
          active->fetch_sub(1);
        }));
      }
    }

    start_barrier->store(true, std::memory_order_release);
    for (auto &future : futures) {
      future.get();
    }
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start_time);
    stats = this->stats();
    return VMWorkerActorBenchResult{owners,
                                    tasks_per_owner,
                                    total_tasks,
                                    stats.worker_count,
                                    max_parallel->load(),
                                    max_owner_parallel->load(),
                                    elapsed.count(),
                                    checksum->load()};
  }

  VMWorkerSnapshotDigestResult snapshot_digest(std::string owner_key, std::string snapshot_text, int repeat) {
    if (owner_key.empty()) {
      owner_key = "global";
    }
    repeat = std::clamp(repeat, 1, 10000);
    start(0);

    auto input_bytes = static_cast<uint64_t>(snapshot_text.size());
    auto checksum = std::make_shared<std::atomic<uint64_t>>(0);
    auto start_time = std::chrono::steady_clock::now();
    auto future = submit_keyed(owner_key, [snapshot_text = std::move(snapshot_text), checksum, repeat] {
      uint64_t local = 1469598103934665603ULL;
      for (int i = 0; i < repeat; i++) {
        for (auto ch : snapshot_text) {
          local ^= static_cast<unsigned char>(ch);
          local *= 1099511628211ULL;
        }
        local ^= static_cast<uint64_t>(i + 1);
        local *= 1099511628211ULL;
      }
      checksum->store(local);
    });
    future.get();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start_time);
    auto stats = this->stats();
    return VMWorkerSnapshotDigestResult{owner_key, stats.worker_count, elapsed.count(),
                                        input_bytes, repeat, checksum->load()};
  }

  VMWorkerActorScoreResult actor_score(std::string owner_key, VMWorkerActorScoreInput input) {
    if (owner_key.empty()) {
      owner_key = "global";
    }
    start(0);

    auto result = std::make_shared<VMWorkerActorScoreResult>();
    result->owner_key = owner_key;
    auto start_time = std::chrono::steady_clock::now();
    auto future = submit_keyed(owner_key, [result, input] {
      fill_actor_score_result(result.get(), input);
    });
    future.get();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start_time);
    auto stats = this->stats();
    result->worker_count = stats.worker_count;
    result->elapsed_ms = elapsed.count();
    return *result;
  }

  VMWorkerCombatDamageResult combat_damage(std::string owner_key, VMWorkerCombatDamageInput input) {
    if (owner_key.empty()) {
      owner_key = "global";
    }
    input = normalize_combat_damage_input(input);
    start(0);

    auto result = std::make_shared<VMWorkerCombatDamageResult>();
    result->owner_key = owner_key;
    auto start_time = std::chrono::steady_clock::now();
    auto future = submit_keyed(owner_key, [result, input] {
      fill_combat_damage_result(result.get(), input);
    });
    future.get();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start_time);
    auto stats = this->stats();
    result->worker_count = stats.worker_count;
    result->elapsed_ms = elapsed.count();
    return *result;
  }

  uint64_t submit_actor_score(std::string owner_key, VMWorkerActorScoreInput input,
                              int timeout_ms, int ttl_ms) {
    if (owner_key.empty()) {
      owner_key = "global";
    }
    start(0);

    auto id = next_task_id_++;
    auto input_hash = hash_mix(hash_mix(hash_mix(hash_mix(hash_mix(hash_mix(
        1469598103934665603ULL, static_cast<uint64_t>(input.hp)),
        static_cast<uint64_t>(input.max_hp)), static_cast<uint64_t>(input.mp)),
        static_cast<uint64_t>(input.max_mp)), static_cast<uint64_t>(input.ep)),
        static_cast<uint64_t>(input.max_ep));
    auto started = std::chrono::steady_clock::now();
    {
      std::lock_guard<std::mutex> lock(results_mutex_);
      async_results_[id] = make_async_record(id, "actor_score", owner_key, input_hash,
                                             timeout_ms, ttl_ms);
    }

    submit_keyed(owner_key, [this, id, owner_key, input, started] {
      VMWorkerActorScoreResult score;
      score.owner_key = owner_key;
      fill_actor_score_result(&score, input);
      auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::steady_clock::now() - started);
      auto stats = this->stats();
      score.worker_count = stats.worker_count;
      score.elapsed_ms = elapsed.count();

      std::lock_guard<std::mutex> lock(results_mutex_);
      auto it = async_results_.find(id);
      if (it != async_results_.end() && it->second.state == VMWorkerTaskState::kPending) {
        it->second.state = VMWorkerTaskState::kSucceeded;
        mark_completed(&it->second);
        it->second.actor_score = score;
      }
    });
    return id;
  }

  uint64_t submit_combat_damage(std::string owner_key, VMWorkerCombatDamageInput input,
                                int timeout_ms, int ttl_ms) {
    if (owner_key.empty()) {
      owner_key = "global";
    }
    input = normalize_combat_damage_input(input);
    start(0);

    auto id = next_task_id_++;
    auto input_hash = hash_combat_damage_input(input);
    auto started = std::chrono::steady_clock::now();
    {
      std::lock_guard<std::mutex> lock(results_mutex_);
      async_results_[id] = make_async_record(id, "combat_damage", owner_key, input_hash,
                                             timeout_ms, ttl_ms);
    }

    submit_keyed(owner_key, [this, id, owner_key, input, started] {
      VMWorkerCombatDamageResult damage;
      damage.owner_key = owner_key;
      fill_combat_damage_result(&damage, input);
      auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::steady_clock::now() - started);
      auto stats = this->stats();
      damage.worker_count = stats.worker_count;
      damage.elapsed_ms = elapsed.count();

      std::lock_guard<std::mutex> lock(results_mutex_);
      auto it = async_results_.find(id);
      if (it != async_results_.end() && it->second.state == VMWorkerTaskState::kPending) {
        it->second.state = VMWorkerTaskState::kSucceeded;
        mark_completed(&it->second);
        it->second.combat_damage = damage;
      }
    });
    return id;
  }

  uint64_t submit_benchmark(int tasks, int millis, int timeout_ms, int ttl_ms) {
    tasks = std::clamp(tasks, 1, 64);
    millis = std::clamp(millis, 1, 5000);
    start(0);

    auto id = next_task_id_++;
    auto input_hash = hash_mix(hash_mix(1469598103934665603ULL, static_cast<uint64_t>(tasks)),
                               static_cast<uint64_t>(millis));
    auto stats = this->stats();
    auto state = std::make_shared<AsyncBenchmarkState>();
    state->task_id = id;
    state->tasks = tasks;
    state->worker_count = stats.worker_count;
    state->started = std::chrono::steady_clock::now();
    state->start_barrier = std::make_shared<std::atomic<bool>>(false);
    state->active = std::make_shared<std::atomic<int>>(0);
    state->max_parallel = std::make_shared<std::atomic<int>>(0);
    state->remaining = std::make_shared<std::atomic<int>>(tasks);
    state->checksum = std::make_shared<std::atomic<uint64_t>>(0);

    {
      std::lock_guard<std::mutex> lock(results_mutex_);
      async_results_[id] = make_async_record(id, "bench", "global", input_hash,
                                             timeout_ms, ttl_ms);
    }

    for (int i = 0; i < tasks; i++) {
      submit([this, state, millis, i] { run_async_benchmark_slice(state, millis, i); });
    }
    state->start_barrier->store(true, std::memory_order_release);
    return id;
  }

  uint64_t submit_snapshot_digest(std::string owner_key, std::string snapshot_text, int repeat,
                                  int timeout_ms, int ttl_ms) {
    if (owner_key.empty()) {
      owner_key = "global";
    }
    repeat = std::clamp(repeat, 1, 10000);
    start(0);

    auto id = next_task_id_++;
    auto input_bytes = static_cast<uint64_t>(snapshot_text.size());
    auto input_hash = hash_mix(hash_string(1469598103934665603ULL, snapshot_text),
                               static_cast<uint64_t>(repeat));
    auto started = std::chrono::steady_clock::now();
    {
      std::lock_guard<std::mutex> lock(results_mutex_);
      async_results_[id] = make_async_record(id, "snapshot_digest", owner_key, input_hash,
                                             timeout_ms, ttl_ms);
    }

    submit_keyed(owner_key, [this, id, owner_key, snapshot_text = std::move(snapshot_text), repeat,
                             input_bytes, started] {
      uint64_t checksum = 1469598103934665603ULL;
      for (int i = 0; i < repeat; i++) {
        for (auto ch : snapshot_text) {
          checksum ^= static_cast<unsigned char>(ch);
          checksum *= 1099511628211ULL;
        }
        checksum ^= static_cast<uint64_t>(i + 1);
        checksum *= 1099511628211ULL;
      }
      auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::steady_clock::now() - started);
      auto stats = this->stats();
      VMWorkerSnapshotDigestResult digest{owner_key, stats.worker_count, elapsed.count(),
                                          input_bytes, repeat, checksum};
      std::lock_guard<std::mutex> lock(results_mutex_);
      auto it = async_results_.find(id);
      if (it != async_results_.end() && it->second.state == VMWorkerTaskState::kPending) {
        it->second.state = VMWorkerTaskState::kSucceeded;
        mark_completed(&it->second);
        it->second.snapshot_digest = digest;
      }
    });
    return id;
  }

  VMWorkerTaskResult poll(uint64_t task_id) {
    std::lock_guard<std::mutex> lock(results_mutex_);
    auto it = async_results_.find(task_id);
    if (it == async_results_.end()) {
      return VMWorkerTaskResult{task_id, VMWorkerTaskState::kUnknown, "", {}, {}, {}, {}, {},
                                "unknown worker task id"};
    }

    apply_deadline_locked(&it->second);
    if (is_expired_locked(it->second)) {
      async_results_.erase(it);
      return VMWorkerTaskResult{task_id, VMWorkerTaskState::kUnknown, "", {}, {}, {}, {}, {},
                                "expired worker task result"};
    }

    VMWorkerTaskResult result{task_id, it->second.state, it->second.type, it->second.envelope,
                               it->second.bench, it->second.snapshot_digest,
                               it->second.actor_score, it->second.combat_damage,
                               it->second.error};
    if ((result.state == VMWorkerTaskState::kSucceeded || result.state == VMWorkerTaskState::kFailed) &&
        it->second.envelope.ttl_ms == 0) {
      async_results_.erase(it);
    }
    return result;
  }

  std::vector<VMWorkerTaskResult> poll_many(const std::vector<uint64_t> &task_ids) {
    std::vector<VMWorkerTaskResult> results;
    results.reserve(task_ids.size());
    for (auto task_id : task_ids) {
      results.push_back(poll(task_id));
    }
    return results;
  }

 private:
  AsyncRecord make_async_record(uint64_t id, std::string type, std::string owner_key,
                                uint64_t input_hash, int timeout_ms, int ttl_ms) {
    AsyncRecord record;
    record.type = type;
    record.envelope.task_id = id;
    record.envelope.task_type = type;
    record.envelope.owner_key = owner_key.empty() ? "global" : owner_key;
    record.envelope.submitted_at_ms = now_ms();
    record.envelope.timeout_ms = normalize_timeout_ms(timeout_ms);
    record.envelope.ttl_ms = normalize_ttl_ms(ttl_ms);
    record.envelope.input_hash = input_hash;
    if (record.envelope.timeout_ms > 0) {
      record.envelope.deadline_at_ms = record.envelope.submitted_at_ms + record.envelope.timeout_ms;
    }
    return record;
  }

  void mark_completed(AsyncRecord *record) {
    record->envelope.completed_at_ms = now_ms();
    if (record->envelope.ttl_ms > 0) {
      record->envelope.expires_at_ms = record->envelope.completed_at_ms + record->envelope.ttl_ms;
    }
  }

  void apply_deadline_locked(AsyncRecord *record) {
    if (!record || record->state != VMWorkerTaskState::kPending || record->envelope.deadline_at_ms == 0) {
      return;
    }
    if (now_ms() <= record->envelope.deadline_at_ms) {
      return;
    }
    record->state = VMWorkerTaskState::kFailed;
    record->error = "worker task timed out";
    mark_completed(record);
  }

  bool is_expired_locked(const AsyncRecord &record) const {
    return record.envelope.expires_at_ms > 0 && now_ms() > record.envelope.expires_at_ms;
  }

  std::function<void()> wrap_task(std::function<void()> task,
                                  std::shared_ptr<std::promise<void>> promise,
                                  std::string owner_key = "") {
    return [this, task = std::move(task), promise, owner_key = std::move(owner_key)] {
      active_++;
      try {
        task();
        promise->set_value();
      } catch (...) {
        promise->set_exception(std::current_exception());
      }
      active_--;
      completed_++;
      if (!owner_key.empty()) {
        release_owner_key(owner_key);
      }
    };
  }

  void release_owner_key(const std::string &owner_key) {
    {
      std::lock_guard<std::mutex> lock(mutex_);
      auto queue = owner_queues_.find(owner_key);
      if (queue != owner_queues_.end() && !queue->second.empty()) {
        tasks_.push_back(std::move(queue->second.front()));
        queue->second.pop_front();
        if (queue->second.empty()) {
          owner_queues_.erase(queue);
        }
        update_queue_high_watermark(tasks_.size());
      } else {
        running_owner_keys_.erase(owner_key);
      }
    }
    cv_.notify_one();
  }

  uint64_t owner_queue_depth_locked() const {
    uint64_t depth = 0;
    for (const auto &entry : owner_queues_) {
      depth += entry.second.size();
    }
    return depth;
  }

  void run() {
    Tracer::setThreadName("VM worker");
    while (true) {
      std::function<void()> task;
      {
        std::unique_lock<std::mutex> lock(mutex_);
        cv_.wait(lock, [this] { return stopping_ || !tasks_.empty(); });
        if (stopping_ && tasks_.empty()) {
          return;
        }
        task = std::move(tasks_.front());
        tasks_.pop_front();
      }
      task();
    }
  }

  void update_queue_high_watermark(uint64_t value) {
    auto current = queue_high_watermark_.load();
    while (value > current && !queue_high_watermark_.compare_exchange_weak(current, value)) {
    }
  }

  void run_async_benchmark_slice(std::shared_ptr<AsyncBenchmarkState> state, int millis, int index) {
    while (!state->start_barrier->load(std::memory_order_acquire)) {
      std::this_thread::yield();
    }

    auto running = state->active->fetch_add(1) + 1;
    update_max(*state->max_parallel, running);
    auto end = std::chrono::steady_clock::now() + std::chrono::milliseconds(millis);
    uint64_t local = static_cast<uint64_t>(index + 1);
    while (std::chrono::steady_clock::now() < end) {
      local = local * 2862933555777941757ULL + 3037000493ULL;
    }
    state->checksum->fetch_add(local);
    state->active->fetch_sub(1);

    if (state->remaining->fetch_sub(1) == 1) {
      auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::steady_clock::now() - state->started);
      VMWorkerBenchResult bench{state->tasks, state->worker_count, state->max_parallel->load(),
                                elapsed.count(), state->checksum->load()};
      std::lock_guard<std::mutex> lock(results_mutex_);
      auto it = async_results_.find(state->task_id);
      if (it != async_results_.end() && it->second.state == VMWorkerTaskState::kPending) {
        it->second.state = VMWorkerTaskState::kSucceeded;
        mark_completed(&it->second);
        it->second.bench = bench;
      }
    }
  }

  mutable std::mutex mutex_;
  std::condition_variable cv_;
  bool stopping_{false};
  std::deque<std::function<void()>> tasks_;
  std::unordered_map<std::string, std::deque<std::function<void()>>> owner_queues_;
  std::unordered_set<std::string> running_owner_keys_;
  std::vector<std::thread> workers_;
  std::atomic<uint64_t> submitted_{0};
  std::atomic<uint64_t> completed_{0};
  std::atomic<uint64_t> queue_high_watermark_{0};
  std::atomic<int> active_{0};
  std::atomic<uint64_t> next_task_id_{1};
  mutable std::mutex results_mutex_;
  std::unordered_map<uint64_t, AsyncRecord> async_results_;
};

VMWorkerRuntime &runtime() {
  static VMWorkerRuntime instance;
  return instance;
}

}  // namespace

void vm_worker_start(int requested_workers) { runtime().start(requested_workers); }

void vm_worker_stop() { runtime().stop(); }

VMWorkerStats vm_worker_stats() { return runtime().stats(); }

VMWorkerBenchResult vm_worker_benchmark(int tasks, int millis) {
  tasks = std::clamp(tasks, 1, 64);
  millis = std::clamp(millis, 1, 5000);
  vm_worker_start();

  auto stats = vm_worker_stats();
  auto start_barrier = std::make_shared<std::atomic<bool>>(false);
  auto ready = std::make_shared<std::atomic<int>>(0);
  auto active = std::make_shared<std::atomic<int>>(0);
  auto max_parallel = std::make_shared<std::atomic<int>>(0);
  auto checksum = std::make_shared<std::atomic<uint64_t>>(0);
  std::vector<std::future<void>> futures;
  futures.reserve(tasks);

  auto start = std::chrono::steady_clock::now();
  for (int i = 0; i < tasks; i++) {
    futures.push_back(runtime().submit([=] {
      ready->fetch_add(1);
      while (!start_barrier->load(std::memory_order_acquire)) {
        std::this_thread::yield();
      }
      auto running = active->fetch_add(1) + 1;
      update_max(*max_parallel, running);
      auto end = std::chrono::steady_clock::now() + std::chrono::milliseconds(millis);
      uint64_t local = static_cast<uint64_t>(i + 1);
      while (std::chrono::steady_clock::now() < end) {
        local = local * 2862933555777941757ULL + 3037000493ULL;
      }
      checksum->fetch_add(local);
      active->fetch_sub(1);
    }));
  }

  auto barrier_target = std::min(tasks, std::max(1, stats.worker_count));
  while (ready->load() < barrier_target) {
    std::this_thread::yield();
  }
  start_barrier->store(true, std::memory_order_release);
  for (auto &future : futures) {
    future.get();
  }
  auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
      std::chrono::steady_clock::now() - start);
  stats = vm_worker_stats();
  return VMWorkerBenchResult{tasks, stats.worker_count, max_parallel->load(), elapsed.count(),
                             checksum->load()};
}

VMWorkerActorBenchResult vm_worker_actor_benchmark(int owners, int tasks_per_owner, int millis) {
  return runtime().actor_benchmark(owners, tasks_per_owner, millis);
}

VMWorkerSnapshotDigestResult vm_worker_snapshot_digest(std::string owner_key,
                                                       std::string snapshot_text,
                                                       int repeat) {
  return runtime().snapshot_digest(std::move(owner_key), std::move(snapshot_text), repeat);
}

VMWorkerActorScoreResult vm_worker_actor_score(std::string owner_key,
                                                VMWorkerActorScoreInput input) {
  return runtime().actor_score(std::move(owner_key), input);
}

VMWorkerCombatDamageResult vm_worker_combat_damage(std::string owner_key,
                                                   VMWorkerCombatDamageInput input) {
  return runtime().combat_damage(std::move(owner_key), input);
}

uint64_t vm_worker_submit_benchmark(int tasks, int millis) {
  return runtime().submit_benchmark(tasks, millis, 0, 0);
}

uint64_t vm_worker_submit_benchmark_v2(int tasks, int millis, int timeout_ms, int ttl_ms) {
  return runtime().submit_benchmark(tasks, millis, timeout_ms, ttl_ms);
}

uint64_t vm_worker_submit_snapshot_digest(std::string owner_key,
                                           std::string snapshot_text,
                                           int repeat) {
  return runtime().submit_snapshot_digest(std::move(owner_key), std::move(snapshot_text), repeat, 0, 0);
}

uint64_t vm_worker_submit_snapshot_digest_v2(std::string owner_key,
                                             std::string snapshot_text,
                                             int repeat,
                                             int timeout_ms,
                                             int ttl_ms) {
  return runtime().submit_snapshot_digest(std::move(owner_key), std::move(snapshot_text), repeat,
                                          timeout_ms, ttl_ms);
}

uint64_t vm_worker_submit_actor_score(std::string owner_key,
                                       VMWorkerActorScoreInput input) {
  return runtime().submit_actor_score(std::move(owner_key), input, 0, 0);
}

uint64_t vm_worker_submit_actor_score_v2(std::string owner_key,
                                          VMWorkerActorScoreInput input,
                                          int timeout_ms,
                                          int ttl_ms) {
  return runtime().submit_actor_score(std::move(owner_key), input, timeout_ms, ttl_ms);
}

uint64_t vm_worker_submit_combat_damage_v2(std::string owner_key,
                                           VMWorkerCombatDamageInput input,
                                           int timeout_ms,
                                           int ttl_ms) {
  return runtime().submit_combat_damage(std::move(owner_key), input, timeout_ms, ttl_ms);
}

VMWorkerTaskResult vm_worker_poll_task(uint64_t task_id) { return runtime().poll(task_id); }

std::vector<VMWorkerTaskResult> vm_worker_poll_tasks(const std::vector<uint64_t> &task_ids) {
  return runtime().poll_many(task_ids);
}
