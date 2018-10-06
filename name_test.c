
struct latency_t {
    u64 ts;
    u64 ns;
    u32 dir; // 1: send, 2: recv
};
BPF_PERF_OUTPUT(events);

BPF_HASH(start, u64);
BPF_HASH(on_wire, u64);
BPF_HASH(addr, u64, struct sk_buff *);
BPF_HASH(prev_len, u64, unsigned int);

TRACEPOINT_PROBE(net, net_dev_xmit) {
   char devname[16];
   TP_DATA_LOC_READ_CONST(&devname[0], name, sizeof(devname));
   bpf_trace_printk("name: %s\n", devname);
   return 0;
}
