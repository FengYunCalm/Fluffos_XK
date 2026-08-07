#include "base/package_api.h"

#include <cerrno>
#include <cstring>
#include <cstdlib>  // for exit
#include <iterator>
#include <string>
#include <thread>
#include <utility>
#include <vector>
#include <fmt/format.h>

#include <event2/event.h>

#include "include/socket_err.h"
#include "packages/sockets/socket_efuns.h"

#ifndef _WIN32
#include <sstream>
#include <spawn.h>
#include <sys/wait.h>

template <typename Out>
void split(const std::string &s, char delim, Out result) {
  std::istringstream iss(s);
  std::string item;
  while (std::getline(iss, item, delim)) {
    *result++ = item;
  }
}

int external_start(int which, svalue_t *args, svalue_t *arg1, svalue_t *arg2, svalue_t *arg3) {
  if (which < 0 || which >= g_num_external_cmds || external_cmd[which] == nullptr ||
      external_cmd[which][0] == '\0') {
    debug(external_start, "external_start: command is empty\n");
    return EESOCKET;
  }

  std::vector<std::string> newargs_data = {std::string(external_cmd[which])};
  if (args->type == T_ARRAY) {
    for (int i = 0; i < args->u.arr->size; i++) {
      auto item = args->u.arr->item[i];
      if (item.type != T_STRING) {
        error("Bad argument list item %d to external_start()\n", i);
      }
      newargs_data.push_back(item.u.string);
    }
  } else {
    split(std::string(args->u.string), ' ', std::back_inserter(newargs_data));
  }

  std::vector<char *> newargs;
  for (auto &arg : newargs_data) {
    newargs.push_back(arg.data());
  }
  newargs.push_back(nullptr);

  posix_spawn_file_actions_t file_actions;
  int ret = posix_spawn_file_actions_init(&file_actions);
  if (ret != 0) {
    debug(external_start, "external_start: posix_spawn_file_actions_init() error: %s\n", strerror(ret));
    return EESOCKET;
  }
  DEFER { posix_spawn_file_actions_destroy(&file_actions); };

  evutil_socket_t sv[2] = {-1, -1};
  if (evutil_socketpair(PF_UNIX, SOCK_STREAM, 0, sv) == -1) {
    return EESOCKET;
  }
  DEFER {
    if (sv[0] >= 0) {
      evutil_closesocket(sv[0]);
    }
    if (sv[1] >= 0) {
      evutil_closesocket(sv[1]);
    }
  };
  if (evutil_make_socket_nonblocking(sv[0]) == -1 ||
      evutil_make_socket_nonblocking(sv[1]) == -1 ||
      evutil_make_socket_closeonexec(sv[0]) == -1 ||
      evutil_make_socket_closeonexec(sv[1]) == -1) {
    return EESOCKET;
  }

  for (int child_fd = 0; child_fd <= 2; ++child_fd) {
    ret = posix_spawn_file_actions_adddup2(&file_actions, sv[1], child_fd);
    if (ret != 0) {
      debug(external_start,
            "external_start: posix_spawn_file_actions_adddup2() error: %s\n",
            strerror(ret));
      return EESOCKET;
    }
  }
  for (const auto endpoint : sv) {
    if (endpoint <= 2) {
      continue;
    }
    ret = posix_spawn_file_actions_addclose(&file_actions, endpoint);
    if (ret != 0) {
      debug(external_start,
            "external_start: posix_spawn_file_actions_addclose() error: %s\n",
            strerror(ret));
      return EESOCKET;
    }
  }

  int fd = find_new_socket();
  if (fd < 0) {
    return fd;
  }

  pid_t pid;
  char *newenviron[] = {nullptr};
  ret = posix_spawn(&pid, newargs[0], &file_actions, nullptr, newargs.data(), newenviron);
  if (ret) {
    debug(external_start, "external_start: posix_spawn() error: %s\n", strerror(ret));
    return EESOCKET;
  }

  evutil_closesocket(sv[1]);
  sv[1] = -1;

  auto *sock = lpc_socks_get(fd);
  new_lpc_socket_event_listener(fd, sock, sv[0]);

  sock->fd = sv[0];
  sock->flags = S_EXTERNAL;
  set_read_callback(fd, arg1);
  set_write_callback(fd, arg2);
  set_close_callback(fd, arg3);
  sock->owner_ob = current_object;
  sock->mode = STREAM;
  sock->state = STATE_DATA_XFER;
  memset(reinterpret_cast<char *>(&sock->l_addr), 0, sizeof(sock->l_addr));
  memset(reinterpret_cast<char *>(&sock->r_addr), 0, sizeof(sock->r_addr));
  sock->release_ob = nullptr;
  sock->r_buf = nullptr;
  sock->r_off = 0;
  sock->r_len = 0;
  sock->w_buf = nullptr;
  sock->w_off = 0;
  sock->w_len = 0;

  current_object->flags |= O_EFUN_SOCKET;
  event_add(sock->ev_write, nullptr);
  event_add(sock->ev_read, nullptr);
  sv[0] = -1;

  debug(external_start, "external_start: Launching external command '%s %s', pid: %jd.\n", external_cmd[which],
                args->type == T_STRING ? args->u.string : "<ARRAY>", (intmax_t)pid);

  std::thread([=]() {
    int status = 0;
    for (;;) {
      const int s = waitpid(pid, &status, WUNTRACED | WCONTINUED);
      if (s == -1 && errno == EINTR) {
        continue;
      }
      if (s == -1) {
        debug(external_start, "external_start: waitpid() error: %s (%d).\n", strerror(errno), errno);
        return;
      }
      std::string status_message =
          fmt::format(FMT_STRING("external_start(): child {} status: "), pid);
      if (WIFEXITED(status)) {
        status_message += fmt::format(FMT_STRING("exited, status={}\n"), WEXITSTATUS(status));
      } else if (WIFSIGNALED(status)) {
        status_message += fmt::format(FMT_STRING("killed by signal {}\n"), WTERMSIG(status));
      } else if (WIFSTOPPED(status)) {
        status_message += fmt::format(FMT_STRING("stopped by signal {}\n"), WSTOPSIG(status));
      } else if (WIFCONTINUED(status)) {
        status_message += "continued\n";
      }

      debug(external_start, "external_start: %s\n", status_message.c_str());
      if (WIFEXITED(status) || WIFSIGNALED(status)) {
        break;
      }
    }
  }).detach();

  return fd;
}
#endif

namespace {
std::string quote_argument(const std::string &arg) {
  if (arg.empty()) {
    return "\"\"";
  }
  if (arg.find_first_of(" \t\n\v\"") == std::string::npos) {
    return arg;
  }
  std::string res = "\"";
  // from
  // https://learn.microsoft.com/en-us/archive/blogs/twistylittlepassagesallalike/everyone-quotes-command-line-arguments-the-wrong-way
  for (auto It = arg.begin();; ++It) {
    unsigned NumberBackslashes = 0;

    while (It != arg.end() && *It == '\\') {
      ++It;
      ++NumberBackslashes;
    }

    if (It == arg.end()) {
      //
      // Escape all backslashes, but let the terminating
      // double quotation mark we add below be interpreted
      // as a metacharacter.
      //
      res.append(NumberBackslashes * 2, '\\');
      break;
    } else if (*It == '"') {
      //
      // Escape all backslashes and the following
      // double quotation mark.
      //
      res.append(NumberBackslashes * 2 + 1, '\\');
      res.push_back(*It);
    } else {
      //
      // Backslashes aren't special here.
      //
      res.append(NumberBackslashes, '\\');
      res.push_back(*It);
    }
  }
  res.push_back('"');
  return res;
}
}  // namespace

#ifdef _WIN32
#include <windows.h>
extern int socketpair_win32(SOCKET socks[2], int make_overlapped);  // in socketpair.cc

int external_start(int which, svalue_t *args, svalue_t *arg1, svalue_t *arg2, svalue_t *arg3) {
  if (which < 0 || which >= g_num_external_cmds || external_cmd[which] == nullptr) {
    debug(external_start, "external_start: command is empty\n");
    return EESOCKET;
  }

  std::string cmd = external_cmd[which];
  // guard against long path with spaces.
  cmd = trim(std::move(cmd));
  if (cmd.empty()) {
    debug(external_start, "external_start: command is empty\n");
    return EESOCKET;
  }
  if (cmd[0] != '"') {
    cmd = fmt::format("\"{}\"", cmd);
  }
  std::string cmdline = cmd + " ";

  if (args->type == T_ARRAY) {
    std::vector<std::string> argv;
    argv.reserve(args->u.arr->size);
    for (int i = 0; i < args->u.arr->size; i++) {
      auto item = args->u.arr->item[i];
      if (item.type != T_STRING) {
        error("Bad argument list item %d to external_start()\n", i);
      }
      argv.emplace_back(quote_argument(item.u.string));
    }
    cmdline += fmt::to_string(fmt::join(argv.begin(), argv.end(), " "));
  } else {
    cmdline += std::string(args->u.string);
  }

  SOCKET sv[2] = {INVALID_SOCKET, INVALID_SOCKET};
  if (socketpair_win32(sv, 0) == SOCKET_ERROR) {
    debug(external_start, "external_start: socketpair_win32() failed: %lu\n",
          static_cast<unsigned long>(WSAGetLastError()));
    return EESOCKET;
  }
  DEFER {
    if (sv[0] != INVALID_SOCKET) {
      closesocket(sv[0]);
    }
    if (sv[1] != INVALID_SOCKET) {
      closesocket(sv[1]);
    }
  };

  if (evutil_make_socket_nonblocking(sv[1]) == -1) {
    debug(external_start, "external_start: failed to make parent socket nonblocking\n");
    return EESOCKET;
  }
  if (!SetHandleInformation(reinterpret_cast<HANDLE>(sv[0]), HANDLE_FLAG_INHERIT,
                            HANDLE_FLAG_INHERIT)) {
    const DWORD error_code = GetLastError();
    debug(external_start, "external_start: failed to make child socket inheritable: %lu\n",
          static_cast<unsigned long>(error_code));
    return EESOCKET;
  }
  if (!SetHandleInformation(reinterpret_cast<HANDLE>(sv[1]), HANDLE_FLAG_INHERIT, 0)) {
    const DWORD error_code = GetLastError();
    debug(external_start, "external_start: failed to make parent socket private: %lu\n",
          static_cast<unsigned long>(error_code));
    return EESOCKET;
  }

  SIZE_T attribute_list_size = 0;
  const BOOL attribute_size_result =
      InitializeProcThreadAttributeList(nullptr, 1, 0, &attribute_list_size);
  const DWORD attribute_size_error = GetLastError();
  if (attribute_size_result != FALSE || attribute_size_error != ERROR_INSUFFICIENT_BUFFER ||
      attribute_list_size == 0) {
    debug(external_start, "external_start: failed to size process attribute list: %lu\n",
          static_cast<unsigned long>(attribute_size_error));
    return EESOCKET;
  }
  std::vector<unsigned char> attribute_storage(attribute_list_size);
  auto *attribute_list = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attribute_storage.data());
  if (!InitializeProcThreadAttributeList(attribute_list, 1, 0, &attribute_list_size)) {
    const DWORD error_code = GetLastError();
    debug(external_start, "external_start: failed to initialize process attribute list: %lu\n",
          static_cast<unsigned long>(error_code));
    return EESOCKET;
  }
  DEFER { DeleteProcThreadAttributeList(attribute_list); };

  HANDLE inherited_handles[] = {reinterpret_cast<HANDLE>(sv[0])};
  if (!UpdateProcThreadAttribute(attribute_list, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                                 inherited_handles, sizeof(inherited_handles), nullptr, nullptr)) {
    const DWORD error_code = GetLastError();
    debug(external_start, "external_start: failed to restrict inherited handles: %lu\n",
          static_cast<unsigned long>(error_code));
    return EESOCKET;
  }

  STARTUPINFOEXA startup_info{};
  startup_info.StartupInfo.cb = sizeof(startup_info);
  startup_info.StartupInfo.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
  startup_info.StartupInfo.wShowWindow = SW_HIDE;
  startup_info.StartupInfo.hStdInput = reinterpret_cast<HANDLE>(sv[0]);
  startup_info.StartupInfo.hStdError = reinterpret_cast<HANDLE>(sv[0]);
  startup_info.StartupInfo.hStdOutput = reinterpret_cast<HANDLE>(sv[0]);
  startup_info.lpAttributeList = attribute_list;
  PROCESS_INFORMATION process_info{};

  // Start the child process with only the stdio socket in its handle table.
  if (!CreateProcessA(nullptr, cmdline.data(), nullptr, nullptr, TRUE,
                      EXTENDED_STARTUPINFO_PRESENT, nullptr, nullptr,
                      reinterpret_cast<LPSTARTUPINFOA>(&startup_info), &process_info)) {
    const DWORD error_code = GetLastError();
    debug(external_start, "external_start: CreateProcess() failed: %lu\n",
          static_cast<unsigned long>(error_code));
    return EESOCKET;
  }

  auto terminate_child = [&]() {
    if (process_info.hProcess != nullptr) {
      if (TerminateProcess(process_info.hProcess, 1)) {
        constexpr DWORD kProcessCleanupTimeoutMs = 5000;
        WaitForSingleObject(process_info.hProcess, kProcessCleanupTimeoutMs);
      } else {
        const DWORD error_code = GetLastError();
        debug(external_start, "external_start: failed to terminate child process: %lu\n",
              static_cast<unsigned long>(error_code));
      }
      CloseHandle(process_info.hProcess);
      process_info.hProcess = nullptr;
    }
  };
  bool child_cleanup_needed = true;
  DEFER {
    if (child_cleanup_needed) {
      terminate_child();
    }
  };

  if (process_info.hThread != nullptr) {
    CloseHandle(process_info.hThread);
    process_info.hThread = nullptr;
  }
  closesocket(sv[0]);
  sv[0] = INVALID_SOCKET;

  const int fd = find_new_socket();
  if (fd < 0) {
    return fd;
  }
  auto *sock = lpc_socks_get(fd);
  sock->fd = sv[1];
  sv[1] = INVALID_SOCKET;
  sock->flags = S_EXTERNAL;
  set_read_callback(fd, arg1);
  set_write_callback(fd, arg2);
  set_close_callback(fd, arg3);
  sock->owner_ob = current_object;
  sock->mode = STREAM;
  sock->state = STATE_DATA_XFER;
  memset(reinterpret_cast<char *>(&sock->l_addr), 0, sizeof(sock->l_addr));
  memset(reinterpret_cast<char *>(&sock->r_addr), 0, sizeof(sock->r_addr));
  sock->release_ob = nullptr;
  sock->r_buf = nullptr;
  sock->r_off = 0;
  sock->r_len = 0;
  sock->w_buf = nullptr;
  sock->w_off = 0;
  sock->w_len = 0;

  new_lpc_socket_event_listener(fd, sock, sock->fd);
  if (sock->ev_read == nullptr || sock->ev_write == nullptr ||
      event_add(sock->ev_write, nullptr) != 0 || event_add(sock->ev_read, nullptr) != 0) {
    debug(external_start, "external_start: failed to register socket events\n");
    socket_close(fd, 0);
    return EESOCKET;
  }
  current_object->flags |= O_EFUN_SOCKET;

  const auto process_handle = process_info.hProcess;
  const auto process_id = process_info.dwProcessId;
  try {
    std::thread([process_handle, process_id]() {
      WaitForSingleObject(process_handle, INFINITE);
      DWORD exit_code = static_cast<DWORD>(-1);
      GetExitCodeProcess(process_handle, &exit_code);
      debug(external_start, "external_start: pid: %lu exited with %lu.\n",
            static_cast<unsigned long>(process_id), static_cast<unsigned long>(exit_code));
      CloseHandle(process_handle);
    }).detach();
  } catch (...) {
    debug(external_start, "external_start: failed to create process monitor thread\n");
    socket_close(fd, 0);
    return EESOCKET;
  }
  process_info.hProcess = nullptr;
  child_cleanup_needed = false;

  debug(external_start, "external_start: Launching external command '%s', pid: %lu.\n",
        cmdline.c_str(), static_cast<unsigned long>(process_id));
  return fd;
}
#endif

#ifdef F_EXTERNAL_START
void f_external_start() {
  int fd, num_arg = st_num_arg;
  svalue_t *arg = sp - num_arg + 1;

  if (!check_valid_socket("external", -1, current_object, "N/A", -1)) {
    pop_n_elems(num_arg - 1);
    sp->u.number = EESECURITY;
    return;
  }

  auto which = arg[0].u.number;
  if (--which < 0 || which > (g_num_external_cmds - 1) || !external_cmd[which]) {
    error("Bad argument 1 to external_start()\n");
  }

  fd = external_start(which, arg + 1, arg + 2, arg + 3, (num_arg == 5 ? arg + 4 : nullptr));
  pop_n_elems(num_arg - 1);
  sp->u.number = fd;
}
#endif
