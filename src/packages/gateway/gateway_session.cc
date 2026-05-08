#include "base/package_api.h"

#include "gateway.h"

#include "base/internal/external_port.h"
#include "comm.h"
#include "packages/core/dns.h"
#include "user.h"

#include <event2/event.h>
#include <nlohmann/json.hpp>

#include <cstdarg>
#include <cstdio>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

namespace {
std::unordered_map<std::string, std::unique_ptr<GatewaySession>> g_gateway_sessions;
std::unordered_map<object_t *, GatewaySession *> g_gateway_obj_to_session;

bool gateway_object_valid(object_t *ob) {
  return ob && !(ob->flags & O_DESTRUCTED) && ob->obname && ob->obname[0] != '\0';
}

void gateway_debugf(const char *fmt, ...) {
  va_list args;
  char buffer[1024];

  if (!g_gateway_debug) {
    return;
  }
  va_start(args, fmt);
  vsnprintf(buffer, sizeof(buffer), fmt, args);
  va_end(args);
  debug_message("%s", buffer);
}

void cleanup_temp_gateway_interactive(object_t *owner) {
  auto *ip = owner ? owner->interactive : nullptr;
  if (!ip) {
    return;
  }

  if (ip->ev_command) {
    evtimer_del(ip->ev_command);
    event_free(ip->ev_command);
    ip->ev_command = nullptr;
  }
  if (ip->gateway_session_id) {
    FREE_MSTR(ip->gateway_session_id);
    ip->gateway_session_id = nullptr;
  }
  if (ip->gateway_real_ip) {
    FREE_MSTR(ip->gateway_real_ip);
    ip->gateway_real_ip = nullptr;
  }

  user_del(ip);
  FREE(ip);
  owner->interactive = nullptr;
}

void gateway_command_callback(evutil_socket_t /*fd*/, short /*what*/, void *arg) {
  auto *user = reinterpret_cast<interactive_t *>(arg);
  if (!user) {
    return;
  }

  if (g_gateway_debug && user->gateway_session_id) {
    debug_message("[gateway] command_callback begin sid=%s\n", user->gateway_session_id);
  }

  set_eval(max_eval_cost);
  process_user_command(user);
  current_interactive = nullptr;
}

object_t *resolve_active_session_owner(const char *session_id, object_t *fallback = nullptr) {
  auto *sess = gateway_find_session(session_id);
  if (sess && gateway_object_valid(sess->user_ob) && sess->user_ob->interactive &&
      sess->user_ob->interactive->ob == sess->user_ob) {
    return sess->user_ob;
  }
  if (gateway_object_valid(fallback) && fallback->interactive &&
      fallback->interactive->ob == fallback) {
    return fallback;
  }
  return nullptr;
}
}  // namespace

int gateway_get_session_count() { return static_cast<int>(g_gateway_sessions.size()); }

GatewaySession *gateway_find_session(const char *session_id) {
  if (!session_id || session_id[0] == '\0') {
    return nullptr;
  }
  auto it = g_gateway_sessions.find(session_id);
  return it == g_gateway_sessions.end() ? nullptr : it->second.get();
}

GatewaySession *gateway_find_session_by_object(object_t *ob) {
  if (!gateway_object_valid(ob)) {
    return nullptr;
  }
  auto it = g_gateway_obj_to_session.find(ob);
  if (it == g_gateway_obj_to_session.end()) {
    return nullptr;
  }

  auto *sess = it->second;
  if (!sess || !gateway_object_valid(sess->user_ob) || sess->user_ob != ob ||
      sess->user_ob_load_time != ob->load_time) {
    g_gateway_obj_to_session.erase(it);
    return nullptr;
  }
  return sess;
}

int gateway_bind_session_object(const char *session_id, object_t *ob, const char *ip, int port,
                                int master_fd) {
  GatewaySession *sess;

  if (!gateway_object_valid(ob) || !session_id || session_id[0] == '\0') {
    return 0;
  }

  sess = gateway_find_session(session_id);
  if (!sess) {
    if (g_gateway_max_sessions > 0 && gateway_get_session_count() >= g_gateway_max_sessions) {
      return 0;
    }
    auto created = std::make_unique<GatewaySession>();
    created->session_id = session_id;
    created->connected_at = get_current_time();
    created->last_active = created->connected_at;
    sess = created.get();
    g_gateway_sessions[session_id] = std::move(created);
  }

  sess->real_ip = ip ? ip : "";
  sess->real_port = port;
  sess->master_fd = master_fd;
  sess->user_ob = ob;
  sess->user_ob_load_time = ob->load_time;
  sess->last_active = get_current_time();
  g_gateway_obj_to_session[ob] = sess;
  return 1;
}

void gateway_unbind_session_object(object_t *ob) {
  auto *sess = gateway_find_session_by_object(ob);
  if (!sess) {
    return;
  }
  g_gateway_obj_to_session.erase(ob);
  g_gateway_sessions.erase(sess->session_id);
}

void gateway_cleanup_master_sessions(int master_fd) {
  std::vector<std::string> to_remove;

  for (const auto &entry : g_gateway_sessions) {
    if (entry.second && entry.second->master_fd == master_fd) {
      to_remove.push_back(entry.first);
    }
  }

  for (const auto &session_id : to_remove) {
    gateway_destroy_session_internal(session_id.c_str(), "gateway_lost", "gateway lost");
  }
}

bool gateway_is_session(object_t *ob) {
  return ob && ob->interactive && (ob->interactive->iflags & GATEWAY_SESSION);
}

void gateway_session_exec_update(object_t *new_ob, object_t *old_ob) {
  auto *sess = gateway_find_session_by_object(old_ob);

  if (!sess || !new_ob || !old_ob || !new_ob->interactive) {
    return;
  }
  new_ob->interactive->ob = new_ob;
  g_gateway_obj_to_session.erase(old_ob);
  g_gateway_obj_to_session[new_ob] = sess;
  sess->user_ob = new_ob;
  sess->user_ob_load_time = new_ob->load_time;
}

void gateway_handle_remove_interactive(interactive_t *ip) {
  if (!ip || !(ip->iflags & GATEWAY_SESSION)) {
    return;
  }
  gateway_unbind_session_object(ip->ob);
}

int gateway_send_to_session(const char *session_id, const char *data, size_t len) {
  auto *sess = gateway_find_session(session_id);
  nlohmann::json payload;
  std::string encoded;

  if (!sess || sess->master_fd < 0 || !data) {
    return 0;
  }

  payload["type"] = "output";
  payload["cid"] = sess->session_id;
  payload["data"] = std::string(data, len);
  encoded = payload.dump();
  if (g_gateway_debug) {
    debug_message("[gateway] output sid=%s len=%zu\n", session_id, len);
  }
  sess->last_active = get_current_time();
  return gateway_send_raw_to_fd(sess->master_fd, encoded.c_str(), encoded.size());
}

object_t *gateway_create_session_internal(const char *session_id, svalue_t *data_val,
                                          const char *ip, int port, int master_fd) {
  object_t *ob;
  svalue_t *ret;
  interactive_t *user;
  int has_gateway_logon;

  if (!session_id || session_id[0] == '\0' || gateway_find_session(session_id) || !g_event_base ||
      (g_gateway_max_sessions > 0 && gateway_get_session_count() >= g_gateway_max_sessions)) {
    return nullptr;
  }

  if (g_gateway_debug) {
    debug_message("[gateway] create_session sid=%s ip=%s port=%d master_fd=%d\n",
                  session_id, ip ? ip : "", port, master_fd);
  }

  save_command_giver(master_ob);
  master_ob->flags |= O_ONCE_INTERACTIVE;

  user = user_add();
  if (!user) {
    master_ob->flags &= ~O_ONCE_INTERACTIVE;
    restore_command_giver();
    return nullptr;
  }
  user->connection_type = PORT_TYPE_GATEWAY;
  user->ob = master_ob;
  user->last_time = get_current_time();
  user->fd = -1;
  user->local_port = 0;
  user->external_port = -1;
  user->iflags |= GATEWAY_SESSION;
  user->gateway_session_id = string_copy(session_id, "gateway_session_id");
  user->gateway_real_ip = string_copy(ip ? ip : "", "gateway_real_ip");
  user->gateway_real_port = port;
  user->gateway_master_fd = master_fd;
  user->ev_command = evtimer_new(g_event_base, gateway_command_callback, user);
  if (!user->ev_command) {
    cleanup_temp_gateway_interactive(master_ob);
    master_ob->flags &= ~O_ONCE_INTERACTIVE;
    restore_command_giver();
    return nullptr;
  }

  master_ob->interactive = user;
  set_eval(max_eval_cost);
  ret = safe_apply_master_ob(APPLY_CONNECT, 0);
  restore_command_giver();
  if (!ret || ret == (svalue_t *)-1 || ret->type != T_OBJECT) {
    cleanup_temp_gateway_interactive(master_ob);
    master_ob->flags &= ~O_ONCE_INTERACTIVE;
    return nullptr;
  }

  ob = ret->u.ob;
  ob->interactive = master_ob->interactive;
  ob->interactive->ob = ob;
  ob->interactive->iflags |= (HAS_WRITE_PROMPT | HAS_PROCESS_INPUT);
  ob->flags |= O_ONCE_INTERACTIVE;
  master_ob->flags &= ~O_ONCE_INTERACTIVE;
  master_ob->interactive = nullptr;
  add_ref(ob, "gateway_create_session");

  query_name_by_addr(ob);
  save_command_giver(ob);
  set_prompt("> ");
  restore_command_giver();

  if (!gateway_bind_session_object(session_id, ob, ip, port, master_fd)) {
    if (ob->interactive) {
      remove_interactive(ob, 1);
    } else {
      free_object(&ob, "gateway_create_session_failed_bind");
    }
    return nullptr;
  }

  has_gateway_logon = function_exists("gateway_logon", ob, 0) ? 1 : 0;
  save_command_giver(ob);
  current_interactive = ob;
  if (has_gateway_logon) {
    if (data_val) {
      push_svalue(data_val);
      ret = safe_apply("gateway_logon", ob, 1, ORIGIN_DRIVER);
    } else {
      ret = safe_apply("gateway_logon", ob, 0, ORIGIN_DRIVER);
    }
  } else {
    ret = safe_apply("logon", ob, 0, ORIGIN_DRIVER);
  }
  restore_command_giver();
  current_interactive = nullptr;

  if (!ret) {
    auto *active_ob = resolve_active_session_owner(session_id, ob);
    if (active_ob && active_ob->interactive) {
      remove_interactive(active_ob, 0);
    } else {
      gateway_unbind_session_object(ob);
      free_object(&ob, "gateway_create_session_failed_logon");
    }
    return nullptr;
  }

  return resolve_active_session_owner(session_id, ob);
}

int gateway_destroy_session_internal(const char *session_id, const char *reason_code,
                                     const char *reason_text) {
  auto *sess = gateway_find_session(session_id);
  auto *ob = sess ? sess->user_ob : nullptr;
  const char *reason_code_str = reason_code && reason_code[0] ? reason_code : "client_disconnected";
  const char *reason_text_str = reason_text && reason_text[0] ? reason_text : reason_code_str;

  if (!sess) {
    return 0;
  }
  if (gateway_object_valid(ob) && ob->interactive) {
    save_command_giver(ob);
    current_interactive = ob;
    set_eval(max_eval_cost);
    copy_and_push_string(reason_code_str);
    copy_and_push_string(reason_text_str);
    safe_apply("gateway_disconnected", ob, 2, ORIGIN_DRIVER);
    current_interactive = nullptr;
    restore_command_giver();

    if ((sess = gateway_find_session(session_id))) {
      sess->master_fd = -1;
    }
    ob = resolve_active_session_owner(session_id, ob);
    if (!ob || !ob->interactive) {
      if (sess && gateway_object_valid(sess->user_ob)) {
        gateway_unbind_session_object(sess->user_ob);
      } else {
        g_gateway_sessions.erase(session_id);
      }
      return 1;
    }
    remove_interactive(ob, 0);
    return 1;
  }
  if (gateway_object_valid(ob)) {
    gateway_unbind_session_object(ob);
  } else {
    g_gateway_sessions.erase(session_id);
  }
  return 1;
}

int gateway_inject_input_internal(object_t *user, const char *input) {
  interactive_t *ip;
  size_t input_len;

  if (!gateway_is_session(user) || !input) {
    return 0;
  }
  ip = user->interactive;
  input_len = strlen(input);
  while (input_len > 0 && (input[input_len - 1] == '\n' || input[input_len - 1] == '\r')) {
    input_len--;
  }
  if (input_len == 0 || ip->text_end + static_cast<int>(input_len) + 2 >= MAX_TEXT) {
    return 0;
  }

  memcpy(ip->text + ip->text_end, input, input_len);
  ip->text_end += static_cast<int>(input_len);
  ip->text[ip->text_end++] = '\n';
  ip->text[ip->text_end] = '\0';

  if (cmd_in_buf(ip)) {
    ip->iflags |= CMD_IN_BUF;
    if (ip->ev_command) {
      timeval zero = {0, 0};
      evtimer_del(ip->ev_command);
      evtimer_add(ip->ev_command, &zero);
    }
  }

  if (auto *sess = gateway_find_session_by_object(user)) {
    sess->last_active = get_current_time();
    if (g_gateway_debug) {
      debug_message("[gateway] inject_input sid=%s text=%s\n", sess->session_id.c_str(), input);
    }
  }

  return 1;
}

void gateway_check_session_timeouts() {
  std::vector<std::string> to_remove;

  for (const auto &entry : g_gateway_sessions) {
    auto *sess = entry.second.get();
    if (!sess) {
      to_remove.push_back(entry.first);
      continue;
    }
    if (!gateway_has_master(sess->master_fd)) {
      to_remove.push_back(entry.first);
      continue;
    }
    if (!gateway_object_valid(sess->user_ob) || !sess->user_ob->interactive) {
      to_remove.push_back(entry.first);
    }
  }

  for (const auto &session_id : to_remove) {
    gateway_destroy_session_internal(session_id.c_str(), "session_timeout", "session cleanup");
  }
}

void cleanup_gateway_sessions() {
  std::vector<std::string> session_ids;

  session_ids.reserve(g_gateway_sessions.size());
  for (const auto &entry : g_gateway_sessions) {
    session_ids.push_back(entry.first);
  }

  for (const auto &session_id : session_ids) {
    gateway_destroy_session_internal(session_id.c_str(), "gateway_cleanup", "gateway cleanup");
  }

  g_gateway_sessions.clear();
  g_gateway_obj_to_session.clear();
}

void f_gateway_session_send() {
  int num_args = st_num_arg;
  object_t *ob = num_args >= 1 ? (sp - num_args + 1)->u.ob : nullptr;
  svalue_t *data_sv = num_args >= 2 ? (sp - num_args + 2) : nullptr;
  GatewaySession *sess = gateway_find_session_by_object(ob);
  nlohmann::json payload;
  std::string payload_json;
  std::string encoded;
  int result = 0;

  if (!sess || !data_sv || !gateway_svalue_to_json_string(data_sv, &payload_json)) {
    pop_n_elems(num_args);
    push_number(0);
    return;
  }

  try {
    payload = nlohmann::json::parse(payload_json);
  } catch (...) {
    pop_n_elems(num_args);
    push_number(0);
    return;
  }

  if (payload.is_object()) {
    payload["cid"] = sess->session_id;
  } else {
    payload = nlohmann::json{
        {"type", "output"},
        {"cid", sess->session_id},
        {"data", payload},
    };
  }

  encoded = payload.dump();
  sess->last_active = get_current_time();
  result = gateway_send_raw_to_fd(sess->master_fd, encoded.c_str(), encoded.size());

  pop_n_elems(num_args);
  push_number(result);
}

void f_gateway_create_session() {
  int num_args = st_num_arg;
  svalue_t *args = sp - num_args + 1;
  const char *session_id = args[0].u.string;
  svalue_t *data = num_args >= 2 ? &args[1] : nullptr;
  const char *ip = (num_args >= 3 && args[2].type == T_STRING) ? args[2].u.string : "";
  int port = (num_args >= 4 && args[3].type == T_NUMBER) ? args[3].u.number : 0;
  int master_fd = (num_args >= 5 && args[4].type == T_NUMBER) ? args[4].u.number : -1;
  object_t *ob;

  ob = gateway_create_session_internal(session_id, data, ip, port, master_fd);
  pop_n_elems(num_args);
  if (ob) {
    put_unrefed_object(ob, "f_gateway_create_session");
  } else {
    put_number(0);
  }
}

void f_gateway_destroy_session() {
  const char *session_id = sp->u.string;
  pop_stack();
  put_number(gateway_destroy_session_internal(session_id, "efun_destroy", "efun"));
}

void f_gateway_sessions() {
  array_t *arr;
  int index = 0;

  arr = allocate_array(gateway_get_session_count());
  for (const auto &entry : g_gateway_sessions) {
    if (gateway_object_valid(entry.second->user_ob)) {
      arr->item[index].type = T_OBJECT;
      arr->item[index].u.ob = entry.second->user_ob;
      add_ref(entry.second->user_ob, "gateway_sessions");
      index++;
    }
  }
  arr->size = index;
  push_refed_array(arr);
}

void f_gateway_session_info() {
  auto *ob = sp->u.ob;
  auto *sess = gateway_find_session_by_object(ob);
  mapping_t *map;

  pop_stack();
  if (!sess) {
    put_number(0);
    return;
  }

  map = allocate_mapping(6);
  add_mapping_string(map, "session_id", sess->session_id.c_str());
  add_mapping_string(map, "ip", sess->real_ip.c_str());
  add_mapping_pair(map, "port", sess->real_port);
  add_mapping_pair(map, "master_fd", sess->master_fd);
  add_mapping_pair(map, "connected_at", sess->connected_at);
  add_mapping_pair(map, "last_active", sess->last_active);
  push_refed_mapping(map);
}

void f_gateway_inject_input() {
  const char *input = sp->u.string;
  auto *ob = (sp - 1)->u.ob;

  pop_2_elems();
  put_number(gateway_inject_input_internal(ob, input));
}
