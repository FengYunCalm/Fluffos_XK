#include "base/package_api.h"

#include "net/tls.h"

#include <iterator>

#ifdef F_SYS_NETWORK_PORTS
void f_sys_network_ports() {
  array_t *info;
  int i = 0, p = 0;

  for (i = 0; i < 5; i++) {
    if (external_port[i].port) {
      p++;
    }
  }

  info = allocate_empty_array(p);
  p = 0;

  for (i = 0; i < 5; i++) {
    if (!external_port[i].port) {
      continue;
    }
    array_t *pInfo = allocate_empty_array(4);

    pInfo->item[0].type = T_NUMBER;
    pInfo->item[0].subtype = 0;
    pInfo->item[0].u.number = i + 1;

    pInfo->item[1].type = T_STRING;
    pInfo->item[1].subtype = STRING_CONSTANT;
    pInfo->item[1].u.string = port_kind_name(external_port[i].kind);

    pInfo->item[2].type = T_NUMBER;
    pInfo->item[2].subtype = 0;
    pInfo->item[2].u.number = external_port[i].port;

    pInfo->item[3].type = T_NUMBER;
    pInfo->item[3].subtype = 0;
    pInfo->item[3].u.number =
        !external_port[i].tls_cert.empty() && !external_port[i].tls_key.empty();

    info->item[p].type = T_ARRAY;
    info->item[p].u.arr = pInfo;
    p++;
  }

  push_refed_array(info);
}
#endif

#ifdef F_SYS_RELOAD_TLS
void f_sys_reload_tls() {
  auto port_index_display = sp->u.number;

  DEFER { pop_stack(); };
  // R2-F12 management contract, fixed order: thread first, then
  // authorization, then index/TLS-type validation. A TLS listener context
  // is main-thread state: worker threads must never touch it, and an
  // unauthorized caller must never reach the validation code.
  if (!vm_context_is_main_thread()) {
    error("sys_reload_tls requires the main thread\n");
  }
  // Master-object authorization hook: valid_sys_reload_tls() on the master
  // object must return a truthy value. Fail-closed: a missing master or a
  // missing/erring hook rejects the call.
  auto *authorized = safe_apply_master_ob(APPLY_VALID_SYS_RELOAD_TLS, 0);
  if (authorized == nullptr || authorized == reinterpret_cast<svalue_t *>(-1) ||
      (authorized->type == T_NUMBER && authorized->u.number == 0)) {
    error("sys_reload_tls requires master authorization\n");
  }
  // Validate the 1-based display index *before* converting to a zero-based
  // array index: subtracting 1 from INT64_MIN would be signed overflow, and
  // comparing against sizeof() (bytes, not elements) allowed out-of-bounds
  // indexes such as 6 to reach external_port[5].
  if (port_index_display < 1 || port_index_display > static_cast<LPC_INT>(std::size(external_port))) {
    error("Invalid port index: %" LPC_INT_FMTSTR_P "\n", port_index_display);
  }
  auto port_index = static_cast<size_t>(port_index_display - 1);
  auto *port = &external_port[port_index];
  if (port->kind == PORT_TYPE_UNDEFINED) {
    error("Invalid port index: %" LPC_INT_FMTSTR_P "\n", port_index_display);
  }
  if (port->kind == PORT_TYPE_WEBSOCKET) {
    error("Reloading websocket TLS config is not supported for port %d.\n", port->port);
  } else {
    if (port->ssl == nullptr) {
      error("Port %" LPC_INT_FMTSTR_P " is not TLS enabled\n", port_index_display);
    }
    auto *ctx = tls_server_init(port->tls_cert, port->tls_key);
    if (ctx == nullptr) {
      error("Failed to reload TLS context for port %d\n", port->port);
    }
    // The listener runs on the main thread only (enforced above), so the
    // old context is closed only after the new one is fully initialized:
    // a failed reload never destroys the old SSL_CTX.
    auto *old_ctx = port->ssl;
    tls_server_close(old_ctx);
    port->ssl = ctx;
    debug_message("Reloading TLS config for port %d.\n", port->port);
  }
}
#endif
