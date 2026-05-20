#include <node_api.h>
#include <uv.h>

#include <errno.h>
#include <fcntl.h>
#include <mutex>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <linux/netfilter_ipv4.h>

#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>

namespace {

constexpr size_t kMaxPkt = 65535;
constexpr int kMaxBatch = 32;
constexpr size_t kGlobalPoolCap = 64;

static std::mutex g_pkt_pool_mu;
static void* g_pkt_pool[kGlobalPoolCap];
static size_t g_pkt_pool_n = 0;

static void* pkt_pool_acquire() {
  std::lock_guard<std::mutex> lock(g_pkt_pool_mu);
  if (g_pkt_pool_n > 0) {
    return g_pkt_pool[--g_pkt_pool_n];
  }
  return malloc(kMaxPkt);
}

static void pkt_pool_release(void* p) {
  if (p == nullptr) {
    return;
  }
  std::lock_guard<std::mutex> lock(g_pkt_pool_mu);
  if (g_pkt_pool_n < kGlobalPoolCap) {
    g_pkt_pool[g_pkt_pool_n++] = p;
  } else {
    free(p);
  }
}

static void finalize_external_pkt_pool(napi_env /* env */, void* data, void* /* hint */) {
  pkt_pool_release(data);
}

struct TunSession {
  int fd = -1;
  uv_poll_t poll {};
  napi_env env = nullptr;
  napi_ref read_cb_ref = nullptr;
  bool closed = false;
  bool poll_started = false;
  bool poll_inited = false;
  bool disposed = false;
};

static int tun_alloc(char* dev) {
  struct ifreq ifr {};
  int tun_fd = open("/dev/net/tun", O_RDWR);
  if (tun_fd < 0) {
    return -1;
  }
  ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
  if (dev[0] != '\0') {
    strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);
  }
  if (ioctl(tun_fd, TUNSETIFF, static_cast<void*>(&ifr)) < 0) {
    close(tun_fd);
    return -1;
  }
  strncpy(dev, ifr.ifr_name, IFNAMSIZ);
  dev[IFNAMSIZ - 1] = '\0';
  return tun_fd;
}

static void poll_close_cb(uv_handle_t* handle) {
  auto* s = static_cast<TunSession*>(handle->data);
  free(s);
}

/** Idempotent: останавливает чтение, закрывает fd, uv_close poll (free в callback) или сразу free. */
static void dispose_session(napi_env env, TunSession* s) {
  if (s == nullptr || s->disposed) {
    return;
  }
  s->disposed = true;
  s->closed = true;

  if (s->read_cb_ref != nullptr && env != nullptr) {
    napi_delete_reference(env, s->read_cb_ref);
    s->read_cb_ref = nullptr;
  }

  if (s->poll_started) {
    uv_poll_stop(&s->poll);
    s->poll_started = false;
  }

  if (s->fd >= 0) {
    close(s->fd);
    s->fd = -1;
  }

  if (s->poll_inited && !uv_is_closing(reinterpret_cast<uv_handle_t*>(&s->poll))) {
    s->poll.data = s;
    uv_close(reinterpret_cast<uv_handle_t*>(&s->poll), poll_close_cb);
  } else {
    free(s);
  }
}

static void on_poll(uv_poll_t* handle, int status, int events) {
  auto* s = static_cast<TunSession*>(handle->data);
  if (s == nullptr || s->closed || s->disposed || s->read_cb_ref == nullptr) {
    return;
  }
  if (status < 0) {
    return;
  }
  if ((events & UV_READABLE) == 0) {
    return;
  }

  void* ptrs[kMaxBatch];
  size_t lens[kMaxBatch];
  int nbatch = 0;

  for (;;) {
    if (nbatch >= kMaxBatch) {
      break;
    }
    void* raw = pkt_pool_acquire();
    if (raw == nullptr) {
      break;
    }
    ssize_t n;
    do {
      n = read(s->fd, raw, kMaxPkt);
    } while (n < 0 && errno == EINTR);

    if (n < 0) {
      pkt_pool_release(raw);
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        break;
      }
      break;
    }
    if (n == 0) {
      pkt_pool_release(raw);
      break;
    }
    ptrs[nbatch] = raw;
    lens[nbatch] = static_cast<size_t>(n);
    nbatch++;
  }

  if (nbatch == 0) {
    return;
  }

  napi_env env = s->env;
  napi_handle_scope scope = nullptr;
  if (napi_open_handle_scope(env, &scope) != napi_ok) {
    for (int i = 0; i < nbatch; i++) {
      pkt_pool_release(ptrs[i]);
    }
    return;
  }

  napi_value callback;
  if (napi_get_reference_value(env, s->read_cb_ref, &callback) != napi_ok) {
    for (int i = 0; i < nbatch; i++) {
      pkt_pool_release(ptrs[i]);
    }
    napi_close_handle_scope(env, scope);
    return;
  }

  napi_value arr;
  if (napi_create_array_with_length(env, static_cast<uint32_t>(nbatch), &arr) != napi_ok) {
    for (int i = 0; i < nbatch; i++) {
      pkt_pool_release(ptrs[i]);
    }
    napi_close_handle_scope(env, scope);
    return;
  }

  for (int i = 0; i < nbatch; i++) {
    napi_value ab;
    if (napi_create_external_arraybuffer(
            env,
            ptrs[i],
            lens[i],
            finalize_external_pkt_pool,
            nullptr,
            &ab) != napi_ok) {
      for (int j = i; j < nbatch; j++) {
        pkt_pool_release(ptrs[j]);
      }
      napi_close_handle_scope(env, scope);
      return;
    }
    if (napi_set_element(env, arr, static_cast<uint32_t>(i), ab) != napi_ok) {
      for (int j = i; j < nbatch; j++) {
        pkt_pool_release(ptrs[j]);
      }
      napi_close_handle_scope(env, scope);
      return;
    }
  }

  napi_value argv[1] = {arr};
  napi_value global;
  napi_value ret;
  napi_get_global(env, &global);
  napi_call_function(env, global, callback, 1, argv, &ret);

  napi_close_handle_scope(env, scope);
}

static void finalize_session(napi_env env, void* data, void* /* hint */) {
  dispose_session(env, static_cast<TunSession*>(data));
}

static napi_value close_tun(napi_env env, napi_callback_info info) {
  napi_value this_arg;
  napi_get_cb_info(env, info, nullptr, nullptr, &this_arg, nullptr);

  void* data = nullptr;
  napi_status st = napi_remove_wrap(env, this_arg, &data);
  if (st != napi_ok || data == nullptr) {
    napi_throw_error(env, nullptr, "tun close: already closed or invalid handle");
    return nullptr;
  }

  dispose_session(env, static_cast<TunSession*>(data));

  napi_value u;
  napi_get_undefined(env, &u);
  return u;
}

static napi_value write_packet(napi_env env, napi_callback_info info) {
  size_t argc = 1;
  napi_value args[1];
  napi_value this_arg;
  napi_get_cb_info(env, info, &argc, args, &this_arg, nullptr);

  TunSession* s = nullptr;
  if (napi_unwrap(env, this_arg, reinterpret_cast<void**>(&s)) != napi_ok || s == nullptr) {
    napi_throw_error(env, nullptr, "tun write: invalid handle");
    return nullptr;
  }
  if (s->closed || s->disposed || s->fd < 0) {
    napi_throw_error(env, nullptr, "tun write: closed");
    return nullptr;
  }
  if (argc < 1) {
    napi_throw_type_error(env, nullptr, "tun write: expected Buffer");
    return nullptr;
  }

  bool is_buf = false;
  napi_is_buffer(env, args[0], &is_buf);
  if (!is_buf) {
    napi_throw_type_error(env, nullptr, "tun write: expected Buffer");
    return nullptr;
  }

  void* data = nullptr;
  size_t len = 0;
  if (napi_get_buffer_info(env, args[0], &data, &len) != napi_ok) {
    napi_throw_error(env, nullptr, "tun write: buffer");
    return nullptr;
  }
  if (len == 0 || len > kMaxPkt) {
    napi_throw_range_error(env, nullptr, "tun write: bad length");
    return nullptr;
  }

  ssize_t w = write(s->fd, data, len);
  if (w < 0) {
    char msg[128];
    snprintf(msg, sizeof msg, "tun write: %s", strerror(errno));
    napi_throw_error(env, nullptr, msg);
    return nullptr;
  }

  napi_value u;
  napi_get_undefined(env, &u);
  return u;
}

static napi_value start_read(napi_env env, napi_callback_info info) {
  size_t argc = 1;
  napi_value args[1];
  napi_value this_arg;
  napi_get_cb_info(env, info, &argc, args, &this_arg, nullptr);

  TunSession* s = nullptr;
  if (napi_unwrap(env, this_arg, reinterpret_cast<void**>(&s)) != napi_ok || s == nullptr) {
    napi_throw_error(env, nullptr, "tun startRead: invalid handle");
    return nullptr;
  }
  if (s->closed || s->disposed || s->fd < 0) {
    napi_throw_error(env, nullptr, "tun startRead: closed");
    return nullptr;
  }
  if (argc < 1) {
    napi_throw_type_error(env, nullptr, "tun startRead: expected callback");
    return nullptr;
  }

  napi_valuetype t;
  napi_typeof(env, args[0], &t);
  if (t != napi_function) {
    napi_throw_type_error(env, nullptr, "tun startRead: expected function");
    return nullptr;
  }

  if (s->read_cb_ref != nullptr) {
    napi_delete_reference(env, s->read_cb_ref);
    s->read_cb_ref = nullptr;
  }

  if (napi_create_reference(env, args[0], 1, &s->read_cb_ref) != napi_ok) {
    napi_throw_error(env, nullptr, "tun startRead: ref");
    return nullptr;
  }

  if (!s->poll_inited) {
    uv_loop_t* loop = nullptr;
    if (napi_get_uv_event_loop(env, &loop) != napi_ok) {
      napi_delete_reference(env, s->read_cb_ref);
      s->read_cb_ref = nullptr;
      napi_throw_error(env, nullptr, "tun startRead: no uv loop");
      return nullptr;
    }
    s->poll.data = s;
    if (uv_poll_init(loop, &s->poll, s->fd) != 0) {
      napi_delete_reference(env, s->read_cb_ref);
      s->read_cb_ref = nullptr;
      napi_throw_error(env, nullptr, "tun startRead: uv_poll_init");
      return nullptr;
    }
    s->poll_inited = true;
  }

  if (!s->poll_started) {
    if (uv_poll_start(&s->poll, UV_READABLE, on_poll) != 0) {
      napi_delete_reference(env, s->read_cb_ref);
      s->read_cb_ref = nullptr;
      napi_throw_error(env, nullptr, "tun startRead: uv_poll_start");
      return nullptr;
    }
    s->poll_started = true;
  }

  napi_value u;
  napi_get_undefined(env, &u);
  return u;
}

static napi_value original_dst_ipv4_from_fd(napi_env env, napi_callback_info info) {
  size_t argc = 1;
  napi_value args[1];
  napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);

  if (argc < 1) {
    napi_throw_error(env, nullptr, "originalDstIpv4FromFd: ожидался fd (int)");
    return nullptr;
  }

  int32_t fd = 0;
  if (napi_get_value_int32(env, args[0], &fd) != napi_ok) {
    napi_throw_type_error(env, nullptr, "originalDstIpv4FromFd: fd должен быть int32");
    return nullptr;
  }

  struct sockaddr_in od {};
  socklen_t olen = sizeof(od);
  memset(&od, 0, sizeof(od));

  if (getsockopt(static_cast<int>(fd), SOL_IP, SO_ORIGINAL_DST, static_cast<void*>(&od),
                 &olen) != 0) {
    char msg[512];
    snprintf(msg, sizeof msg,
             "SO_ORIGINAL_DST (нужны iptables REDIRECT к этому сокету): %s",
             strerror(errno));
    napi_throw_error(env, nullptr, msg);
    return nullptr;
  }

  if (od.sin_family != AF_INET) {
    napi_throw_error(env, nullptr, "SO_ORIGINAL_DST: ожидался AF_INET");
    return nullptr;
  }

  char ip[INET_ADDRSTRLEN]{};
  if (inet_ntop(AF_INET, &od.sin_addr, ip, sizeof ip) == nullptr) {
    napi_throw_error(env, nullptr, "inet_ntop(AF_INET)");
    return nullptr;
  }

  const uint16_t port = ntohs(od.sin_port);

  napi_value out{};
  if (napi_create_object(env, &out) != napi_ok) {
    return nullptr;
  }
  napi_value nip{};
  napi_create_string_utf8(env, ip, NAPI_AUTO_LENGTH, &nip);
  napi_set_named_property(env, out, "address", nip);

  napi_value np{};
  napi_create_uint32(env, port, &np);
  napi_set_named_property(env, out, "port", np);

  return out;
}

static napi_value open_tun(napi_env env, napi_callback_info info) {
  size_t argc = 1;
  napi_value args[1];
  napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);

  char dev[IFNAMSIZ] = "";

  if (argc >= 1) {
    napi_valuetype vt;
    napi_typeof(env, args[0], &vt);
    if (vt == napi_string) {
      size_t n = 0;
      napi_get_value_string_utf8(env, args[0], dev, IFNAMSIZ, &n);
    }
  }

  int fd = tun_alloc(dev);
  if (fd < 0) {
    char msg[256];
    snprintf(msg, sizeof msg, "tun open failed: %s", strerror(errno));
    napi_throw_error(env, nullptr, msg);
    return nullptr;
  }

  int fl = fcntl(fd, F_GETFL, 0);
  if (fl < 0 || fcntl(fd, F_SETFL, fl | O_NONBLOCK) < 0) {
    close(fd);
    napi_throw_error(env, nullptr, "tun fcntl O_NONBLOCK failed");
    return nullptr;
  }

  auto* s = static_cast<TunSession*>(calloc(1, sizeof(TunSession)));
  if (s == nullptr) {
    close(fd);
    napi_throw_error(env, nullptr, "tun OOM");
    return nullptr;
  }
  s->fd = fd;
  s->env = env;

  napi_value obj;
  if (napi_create_object(env, &obj) != napi_ok) {
    close(fd);
    free(s);
    napi_throw_error(env, nullptr, "tun create object");
    return nullptr;
  }

  if (napi_wrap(env, obj, s, finalize_session, nullptr, nullptr) != napi_ok) {
    close(fd);
    free(s);
    napi_throw_error(env, nullptr, "tun wrap");
    return nullptr;
  }

  napi_value name;
  napi_create_string_utf8(env, dev, NAPI_AUTO_LENGTH, &name);
  napi_set_named_property(env, obj, "ifname", name);

  napi_value fn_write;
  napi_create_function(env, "write", NAPI_AUTO_LENGTH, write_packet, nullptr, &fn_write);
  napi_set_named_property(env, obj, "write", fn_write);

  napi_value fn_sr;
  napi_create_function(env, "startRead", NAPI_AUTO_LENGTH, start_read, nullptr, &fn_sr);
  napi_set_named_property(env, obj, "startRead", fn_sr);

  napi_value fn_close;
  napi_create_function(env, "close", NAPI_AUTO_LENGTH, close_tun, nullptr, &fn_close);
  napi_set_named_property(env, obj, "close", fn_close);

  return obj;
}

static napi_value init(napi_env env, napi_value exports) {
  napi_value fn;
  napi_create_function(env, "open", NAPI_AUTO_LENGTH, open_tun, nullptr, &fn);
  napi_set_named_property(env, exports, "open", fn);

  napi_value fn_od;
  napi_create_function(env, "originalDstIpv4FromFd", NAPI_AUTO_LENGTH, original_dst_ipv4_from_fd,
                       nullptr, &fn_od);
  napi_set_named_property(env, exports, "originalDstIpv4FromFd", fn_od);
  return exports;
}

}  // namespace

NAPI_MODULE(NODE_GYP_MODULE_NAME, init)
