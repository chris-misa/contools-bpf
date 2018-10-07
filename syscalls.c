#include <uapi/linux/ptrace.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>

struct latency_t {
    u64 ts;
    u64 ns;
    u32 dir; // 1: send, 2: recv
};
BPF_PERF_OUTPUT(events);

BPF_HASH(start, u64);
BPF_HASH(on_wire, u64);

static int str_comp(char *s1, char *s2, int len)
{
    int i;
    for (i = 0; i < len; i++) {
	    if (s1[i] != s2[i]) {
		    return -1;
	    }
    }
    return 0;
}


// 
// Send path events
// 
TRACEPOINT_PROBE(syscalls, sys_enter_sendto)
{
  u64 pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
  u64 ts;
  u64 send_key = 1;
  if (pid == PING_PID) {
    ts = bpf_ktime_get_ns();
    start.update(&send_key, &ts);
  }
  return 0;
}

TRACEPOINT_PROBE(net, net_dev_xmit)
{
  struct sk_buff *skb = (struct sk_buff *)args->skbaddr;
  u64 pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
  char devname[16];
  u64 *tsp, delta;

  u64 send_key = 1;

  struct latency_t lat = {};

  if (pid == PING_PID) {
    tsp = start.lookup(&send_key);
    if (tsp != 0) {
      TP_DATA_LOC_READ_CONST(&devname[0], name, sizeof(devname));
      if (!str_comp(devname, OUTER_DEV_NAME, 16)) {
        lat.ts = bpf_ktime_get_ns();
        lat.ns = lat.ts - *tsp;
        lat.dir = 1;
        events.perf_submit(args, &lat, sizeof(lat));
        start.delete(&send_key);
        on_wire.update(&send_key, &send_key);
      }
    }
  }
  return 0;
}



//
// Receive Path events
//

TRACEPOINT_PROBE(net, netif_receive_skb)
{
    struct sk_buff *skb = (struct sk_buff *)args->skbaddr;
    char devname[16];
    u64 ts;

    u64 send_key = 1;
    u64 recv_key = 2;

    // Make sure we're expecting an echo reply
    if (on_wire.lookup(&send_key) != 0) {

        // Get the device name
        TP_DATA_LOC_READ_CONST(&devname[0], name, sizeof(devname));
        if (!str_comp(devname, OUTER_DEV_NAME, 16)) {
          ts = bpf_ktime_get_ns();
          start.update(&recv_key, &ts);
        }
    }

    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_recvmsg)
{
  u64 pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
  u64 *tsp, delta;
  struct latency_t lat = {};

  u64 send_key = 1;
  u64 recv_key = 2;

  tsp = start.lookup(&recv_key);
  if (tsp != 0) {
    lat.ts = bpf_ktime_get_ns();
    lat.ns = lat.ts - *tsp;
    lat.dir = 2;
    events.perf_submit(args, &lat, sizeof(lat));
    start.delete(&recv_key);
    on_wire.delete(&send_key);
  }

  return 0;
}
