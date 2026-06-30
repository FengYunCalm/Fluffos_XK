#include "base/package_api.h"

#include "packages/async/async.h"

#include <chrono>
#include <cstring>
#include <deque>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

#if HAVE_DIRENT_H
#include <dirent.h>
#else
#define dirent direct
#if HAVE_SYS_NDIR_H
#include <sys/ndir.h>
#endif
#if HAVE_SYS_DIR_H
#include <sys/dir.h>
#endif
#if HAVE_NDIR_H
#include <ndir.h>
#endif
#endif

#include <sys/param.h>  // for MAXPATHLEN
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <zlib.h>
#include <vm/internal/base/function.h>
#include <vm/internal/base/interpret.h>
#include <vm/internal/base/program.h>

#include "vm/context.h"
#include "vm/owner.h"

#ifdef F_ASYNC_DB_EXEC
#include "packages/db/db.h"
#endif

#include "packages/core/file.h"  // check_valid_path, FIXME

namespace {

enum atypes { AREAD, AWRITE, AGETDIR, ADBEXEC, ADONE };

enum astates { BUSY, DONE };

struct Request {
  std::string path;
  std::string owner_id;
  uint64_t owner_epoch{0};
  int flags;
  int ret;
  int handle;
  std::string data;
  function_to_call_t *fun;
  struct Request *next;
  enum atypes type;
  int status;
};

struct Work {
  struct Request *data;
  void *(*func)(struct Request *);
};

std::deque<struct Work *> reqs;
std::mutex reqs_lock;

std::deque<struct Request *> finished_reqs;
std::mutex finished_reqs_lock;

class ControlledLpcScope {
 public:
  ControlledLpcScope() : previous_(vm_context().owner.controlled_lpc_active) {
    vm_context().owner.controlled_lpc_active = true;
  }
  ~ControlledLpcScope() { vm_context().owner.controlled_lpc_active = previous_; }

 private:
  bool previous_;
};

object_t *callback_owner(function_to_call_t *fun) {
  if (!fun) {
    return nullptr;
  }
  return fun->ob ? fun->ob : fun->f.fp ? fun->f.fp->hdr.owner : nullptr;
}

void bind_request_owner(Request *req) {
  auto *owner = callback_owner(req->fun);
  req->owner_id = vm_owner_id(owner);
  req->owner_epoch = vm_owner_epoch(owner);
}

svalue_t *safe_call_async_callback(Request *req, int narg, const char *operation) {
  auto *owner = callback_owner(req->fun);
  if (owner && (owner->flags & O_DESTRUCTED)) {
    vm_owner_record_task_trace(req->owner_id.c_str(), "async_callback", operation, req->owner_epoch, "destructed");
    pop_n_elems(narg);
    return nullptr;
  }
  if (owner && (req->owner_id != vm_owner_id(owner) || req->owner_epoch != vm_owner_epoch(owner))) {
    vm_owner_record_task_trace(vm_owner_id(owner), "async_callback", operation, vm_owner_epoch(owner), "stale");
    pop_n_elems(narg);
    return nullptr;
  }
  VMOwnerScope owner_scope(vm_context(), owner ? vm_owner_id(owner) : req->owner_id.c_str(),
                           owner ? vm_owner_epoch(owner) : req->owner_epoch);
  vm_owner_record_task_trace(owner ? vm_owner_id(owner) : req->owner_id.c_str(), "async_callback", operation,
                             owner ? vm_owner_epoch(owner) : req->owner_epoch, "dispatched");
  ControlledLpcScope controlled_lpc;
  return safe_call_efun_callback(req->fun, narg);
}

const char *async_operation_name(enum atypes type) {
  switch (type) {
    case AREAD:
      return "async_read";
    case AWRITE:
      return "async_write";
#ifdef F_ASYNC_GETDIR
    case AGETDIR:
      return "async_getdir";
#endif
#ifdef F_ASYNC_DB_EXEC
    case ADBEXEC:
      return "async_db_exec";
#endif
    case ADONE:
    default:
      return "async_done";
  }
}

void free_async_request(Request *req) {
  if (!req) {
    return;
  }
  free_funp(req->fun->f.fp);
  delete req->fun;
  delete req;
}

void cleanup_async_request(Request *req, const char *operation, bool main_required) {
  if (!req) {
    return;
  }
  if (!main_required || vm_context_is_main_thread()) {
    free_async_request(req);
    return;
  }
  auto task_id = vm_owner_enqueue_executor_callback_cleanup(
      req->owner_id.c_str(), req->owner_epoch, "async_callback", operation,
      [req] { free_async_request(req); });
  if (task_id == 0) {
    free_async_request(req);
  }
}

void thread_func() {
  Tracer::setThreadName("Package Async thread");

  ScopedTracer const tracer("Async thread loop");

  while (true) {
    struct Work *w = nullptr;
    {
      std::lock_guard<std::mutex> const lock(reqs_lock);
      if (reqs.empty()) {
        return;
      }
      w = reqs.front();
      reqs.pop_front();
    }

    if (w) {
      {
        ScopedTracer const work_tracer("Async thread work", EventCategory::DEFAULT, [=] {
          return json{{"type", w->data->type}};
        });

        w->func(w->data);
      }
      if (w->data->status == DONE) {
        {
          std::lock_guard<std::mutex> const lock(finished_reqs_lock);
          finished_reqs.push_back(w->data);
        }
        delete w;
      } else {
        std::lock_guard<std::mutex> const lock(reqs_lock);
        reqs.push_back(w);
      }

      add_walltime_event(std::chrono::milliseconds(0),
                         TickEvent::callback_type([] { check_reqs(); }));
    }
  }
}

void do_stuff(void *(*func)(struct Request *), struct Request *data) {
  std::lock_guard<std::mutex> const lock(reqs_lock);

  if (reqs.empty()) {
    std::thread(thread_func).detach();
  }

  auto *i = new Work;
  i->func = func;
  i->data = data;

  reqs.push_back(i);
}

void *gzreadthread(struct Request *req) {
  gzFile file = gzopen(req->path.c_str(), "rb");
  req->ret = gzread(file, (void *)(req->data.data()), req->data.size());
  req->status = DONE;
  gzclose(file);
  return nullptr;
}

int aio_gzread(struct Request *req) {
  req->status = BUSY;
  do_stuff(gzreadthread, req);
  return 0;
}

void *gzwritethread(struct Request *req) {
  int const fd =
      open(req->path.c_str(), req->flags & 1 ? O_CREAT | O_WRONLY | O_TRUNC : O_CREAT | O_WRONLY | O_APPEND,
           S_IRWXU | S_IRWXG);
  gzFile file = gzdopen(fd, "wb");
  req->ret = gzwrite(file, (void *)(req->data.data()), req->data.size());
  req->status = DONE;
  gzclose(file);
  return nullptr;
}

int aio_gzwrite(struct Request *req) {
  req->status = BUSY;
  do_stuff(gzwritethread, req);
  return 0;
}

void *writethread(struct Request *req) {
  int const fd =
      open(req->path.c_str(), req->flags & 1 ? O_CREAT | O_WRONLY | O_TRUNC : O_CREAT | O_WRONLY | O_APPEND,
           S_IRWXU | S_IRWXG);

  req->ret = write(fd, req->data.data(), req->data.size());

  req->status = DONE;
  close(fd);
  return nullptr;
}

int aio_write(struct Request *req) {
  req->status = BUSY;
  do_stuff(writethread, req);
  return 0;
}

void *readthread(struct Request *req) {
  int const fd = open(req->path.c_str(), O_RDONLY);
  auto size = read(fd, (void *)(req->data.data()), req->data.max_size());
  close(fd);
  req->data.resize(size);
  req->ret = size;
  req->status = DONE;
  return nullptr;
}

int aio_read(struct Request *req) {
  req->status = BUSY;
  do_stuff(readthread, req);
  return 0;
}

} // namespace

#ifdef F_ASYNC_DB_EXEC
void *dbexecthread(struct Request *req) {
  ScopedTracer const work_tracer("db_exec", EventCategory::DEFAULT, [=] { return json{req->data}; });

  db_lock_mutex();
  DEFER { db_unlock_mutex(); };
  // see add_db_exec
  db_t *db = find_db_conn(req->handle);
  int ret = -1;
  if (db && db->type->execute) {
    if (db->type->cleanup) {
      db->type->cleanup(&(db->c));
    }

    ret = db->type->execute(&(db->c), req->data.c_str());
    if (ret == -1) {
      if (db->type->error) {
        char *tmp = db->type->error(&(db->c));
        req->path = std::string(tmp);
        FREE_MSTR(tmp);
      } else {
        req->path = "Unknown error";
      }
    }
  } else {
    req->path = std::string("No database exec function!");
  }

  req->ret = ret;
  req->status = DONE;
  return nullptr;
}

int aio_db_exec(struct Request *req) {
  req->status = BUSY;
  do_stuff(dbexecthread, req);
  return 0;
}
#endif

#ifdef F_ASYNC_GETDIR
void *getdirthread(struct Request *req) {
  ScopedTracer const work_tracer("getdir", EventCategory::DEFAULT, [=] { return json{req->path}; });

  DIR *dirp = nullptr;
  if ((dirp = opendir(req->path.c_str())) == nullptr) {
    req->ret = 0;
    req->status = DONE;
    return nullptr;
  }
  /*
   * Count files
   */
  int i = 0;
  for (auto *de = readdir(dirp); de; de = readdir(dirp)) {
    if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0) continue;
    req->data.resize(req->data.size() + sizeof(dirent *));
    memcpy(&((dirent *)(req->data.data()))[i], de, sizeof(*de));
    i++;
  }

  closedir(dirp);

  req->ret = i;
  req->status = DONE;
  return nullptr;
}

int aio_getdir(struct Request *req) {
  req->status = BUSY;
  do_stuff(getdirthread, req);
  return 0;
}

#endif

int add_read(const char *fname, function_to_call_t *fun) {
  const auto read_file_max_size = CONFIG_INT(__MAX_READ_FILE_SIZE__);

  if (fname) {
    auto *req = new Request();
    // printf("fname: %s\n", fname);
    req->data.resize(read_file_max_size);
    req->fun = fun;
    req->type = AREAD;
    req->path = std::string(fname);
    bind_request_owner(req);
    return aio_gzread(req);
  }
  error("permission denied\n");

  return 1;
}

#ifdef F_ASYNC_GETDIR
int add_getdir(const char *fname, function_to_call_t *fun) {
  auto max_array_size = CONFIG_INT(__MAX_ARRAY_SIZE__);

  if (fname) {
    // printf("fname: %s\n", fname);
    auto *req = new Request();
    req->data.resize(max_array_size);
    req->fun = fun;
    req->type = AGETDIR;
    req->path = fname;
    bind_request_owner(req);
    return aio_getdir(req);
  }
  error("permission denied\n");

  return 1;
}
#endif

int add_write(const char *fname, const char *buf, int size, char flags, function_to_call_t *fun) {
  if (!fname) {
    error("permission denied\n");
  }

  auto *req = new Request();
  req->data = std::string(buf, size);
  req->fun = fun;
  req->type = AWRITE;
  req->flags = flags;
  req->path = std::string(fname);
  bind_request_owner(req);
  if (flags & 2) {
    return aio_gzwrite(req);
  }
  return aio_write(req);
}

#ifdef F_ASYNC_DB_EXEC
int add_db_exec(int handle, const char *sql, function_to_call_t *fun) {
  auto *req = new Request();
  req->fun = fun;
  req->type = ADBEXEC;
  req->handle = handle;
  req->data = sql;
  bind_request_owner(req);
  return aio_db_exec(req);
}
#endif

void handle_read(struct Request *req) {
  int const val = req->ret;
  if (val < 0) {
    push_number(val);
    set_eval(max_eval_cost);
    safe_call_async_callback(req, 1, "async_read");
    return;
  }
  char *file = new_string(val, "read_file_async: str");
  memcpy(file, (char *)(req->data.data()), val);
  file[val] = 0;
  push_malloced_string(file);
  set_eval(max_eval_cost);
  safe_call_async_callback(req, 1, "async_read");
}

#ifdef F_ASYNC_GETDIR
void handle_getdir(struct Request *req) {
  auto max_array_size = CONFIG_INT(__MAX_ARRAY_SIZE__);

  int ret_size = req->ret;
  if (ret_size > max_array_size) {
    ret_size = max_array_size;
  }
  array_t *ret = allocate_empty_array(ret_size);
  if (ret_size > 0) {
    for (int i = 0; i < ret_size; i++) {
      auto de = ((struct dirent *)req->data.data())[i];
      svalue_t *vp = &(ret->item[i]);
      vp->type = T_STRING;
      vp->subtype = STRING_MALLOC;
      vp->u.string = string_copy(de.d_name, "encode_stat");
    }

    qsort((void *)ret->item, ret_size, sizeof ret->item[0],
          [](const void *p1, const void *p2) -> int {
            auto *x = (svalue_t *)p1;
            auto *y = (svalue_t *)p2;

            return strcmp(x->u.string, y->u.string);
          });
  }

  push_refed_array(ret);
  set_eval(max_eval_cost);
  safe_call_async_callback(req, 1, "async_getdir");
}
#endif

void handle_write(struct Request *req) {
  int const val = req->ret;
  if (val < 0) {
    push_number(val);
    set_eval(max_eval_cost);
    safe_call_async_callback(req, 1, "async_write");
    return;
  }
  push_undefined();
  set_eval(max_eval_cost);
  safe_call_async_callback(req, 1, "async_write");
}

void handle_db_exec(struct Request *req) {
  int const val = req->ret;
  if (val == -1) {
    copy_and_push_string(req->path.c_str());
  } else {
    push_number(val);
  }
  set_eval(max_eval_cost);
  safe_call_async_callback(req, 1, "async_db_exec");
}

void handle_finished_request(Request *req, enum atypes type) {
  req->type = ADONE;
  switch (type) {
    case AREAD:
      handle_read(req);
      break;
    case AWRITE:
      handle_write(req);
      break;
#ifdef F_ASYNC_GETDIR
    case AGETDIR:
      handle_getdir(req);
      break;
#endif
#ifdef F_ASYNC_DB_EXEC
    case ADBEXEC:
      handle_db_exec(req);
      break;
#endif
    case ADONE:
      // must have had an error while handling it before.
      break;
    default:
      fatal("unknown async type\n");
  }
}

void dispatch_finished_request(Request *req, enum atypes type) {
  auto *owner = callback_owner(req->fun);
  auto operation = std::string(async_operation_name(type));
  if (!owner || (owner->flags & O_DESTRUCTED)) {
    handle_finished_request(req, type);
    free_async_request(req);
    return;
  }

  auto executor_available = vm_owner_executor_available();
  if (executor_available) {
    auto task_id = vm_owner_enqueue_executor_task(
        owner, "async_callback", operation.c_str(),
        [req, type, operation] {
          handle_finished_request(req, type);
          cleanup_async_request(req, operation.c_str(), true);
        },
        [req, operation] { cleanup_async_request(req, operation.c_str(), true); });
    if (task_id != 0) {
      return;
    }
  }

  auto task_id = vm_owner_enqueue_main_task(
      owner, "async_callback", operation.c_str(),
      [req, type] {
        handle_finished_request(req, type);
        free_async_request(req);
      },
      [req] { free_async_request(req); },
      executor_available ? VM_OWNER_MAIN_TASK_EXPLICIT_FALLBACK
                         : VM_OWNER_MAIN_TASK_OFF_MODE_FALLBACK);
  if (task_id == 0) {
    handle_finished_request(req, type);
    free_async_request(req);
  }
}

void check_reqs() {
  ScopedTracer const tracer("Async callback");

  std::deque<struct Request *> ready;
  {
    std::lock_guard<std::mutex> const lock(finished_reqs_lock);
    ready.swap(finished_reqs);
  }

  while (!ready.empty()) {
    auto *req = ready.front();
    ready.pop_front();
    auto const type = req->type;
    dispatch_finished_request(req, type);
  }
  vm_owner_drain_main_tasks(1024);
}

void complete_all_asyncio() {
  while (true) {
    std::lock_guard<std::mutex> const lock(reqs_lock);

    if (reqs.empty()) {
      break;
    }
  }
  check_reqs();
}

int find_test_lfun_index(object_t *owner, const char *method) {
  if (!owner || !owner->prog || !method) {
    return -1;
  }
  for (int i = 0; i < owner->prog->num_functions_defined; i++) {
    auto *entry = find_func_entry(owner->prog, i);
    if (entry && entry->funcname && std::strcmp(entry->funcname, method) == 0) {
      return i;
    }
  }
  return -1;
}

function_to_call_t *make_test_lfun_callback(object_t *owner, int function_index) {
  VMExecutionState execution;
  execution.current_object = owner;
  execution.current_prog = owner ? owner->prog : nullptr;
  VMExecutionScope execution_scope(vm_context(), execution);
  svalue_t no_args{};
  no_args.type = T_NUMBER;
  auto *fun = new function_to_call_t;
  fun->ob = nullptr;
  fun->f.fp = make_lfun_funp(function_index, &no_args);
  fun->narg = 0;
  fun->args = nullptr;
  return fun;
}

bool vm_async_test_support_dispatch_read_callback(object_t *owner, const char *method, const char *payload) {
  auto function_index = find_test_lfun_index(owner, method);
  if (function_index < 0) {
    return false;
  }
  auto *req = new Request();
  req->fun = make_test_lfun_callback(owner, function_index);
  req->type = AREAD;
  req->status = DONE;
  req->data = payload ? payload : "";
  req->ret = static_cast<int>(req->data.size());
  bind_request_owner(req);
  dispatch_finished_request(req, AREAD);
  return true;
}

#ifdef F_ASYNC_READ

void f_async_read() {
  std::unique_ptr<function_to_call_t> cb(new function_to_call_t);
  process_efun_callback(1, cb.get(), F_ASYNC_READ);
  cb->f.fp->hdr.ref++;
  pop_stack();

  add_read(check_valid_path(sp->u.string, current_object, "read_file", 0), cb.release());
  pop_stack();
}
#endif

#ifdef F_ASYNC_WRITE
void f_async_write() {
  std::unique_ptr<function_to_call_t> cb(new function_to_call_t);
  process_efun_callback(3, cb.get(), F_ASYNC_WRITE);
  cb->f.fp->hdr.ref++;
  pop_stack();

  add_write(check_valid_path((sp - 2)->u.string, current_object, "write_file", 1),
            (sp - 1)->u.string, SVALUE_STRLEN((sp - 1)), sp->u.number, cb.release());
  pop_3_elems();
}
#endif

#ifdef F_ASYNC_GETDIR
void f_async_getdir() {
  std::unique_ptr<function_to_call_t> cb(new function_to_call_t);
  process_efun_callback(1, cb.get(), F_ASYNC_GETDIR);
  cb->f.fp->hdr.ref++;
  pop_stack();

  add_getdir(check_valid_path(sp->u.string, current_object, "get_dir", 0), cb.release());
  pop_stack();
}
#endif
#ifdef F_ASYNC_DB_EXEC
void f_async_db_exec() {
  std::unique_ptr<function_to_call_t> cb(new function_to_call_t);
  process_efun_callback(2, cb.get(), F_ASYNC_DB_EXEC);
  cb->f.fp->hdr.ref++;
  pop_stack();

  array_t *info;
  info = allocate_empty_array(1);
  info->item[0].type = T_STRING;
  info->item[0].subtype = STRING_MALLOC;
  info->item[0].u.string = string_copy(sp->u.string, "f_db_exec");
  valid_database("exec", info);

  db_t *db;
#ifdef PACKAGE_ASYNC
  db_lock_mutex();
#endif
  db = find_db_conn((sp - 1)->u.number);
  if (!db) {
#ifdef PACKAGE_ASYNC
    db_unlock_mutex();
#endif
    error("Attempt to exec on an invalid database handle\n");
  }
#ifdef PACKAGE_ASYNC
  db_unlock_mutex();
#endif

  add_db_exec((sp - 1)->u.number, sp->u.string, cb.release());
  pop_2_elems();
}
#endif

void async_mark_request() {
#ifdef DEBUGMALLOC_EXTENSIONS
  std::lock_guard<std::mutex> const lock(reqs_lock);
  std::lock_guard<std::mutex> const flock(finished_reqs_lock);

  for (auto &work : reqs) {
    auto *req = work->data;
    if (req->fun != nullptr) {
      req->fun->f.fp->hdr.extra_ref++;
    }
  }

  for (auto &req : finished_reqs) {
    if (req->fun != nullptr) {
      req->fun->f.fp->hdr.extra_ref++;
    }
  }
#endif
}
