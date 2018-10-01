from bcc import BPF

prog='''
TRACEPOINT_PROBE(net, netif_receive_skb) {
  bpf_trace_printk("Hello receive\\n");
  return 0;
}
'''

b = BPF(text=prog)

b.trace_print()
