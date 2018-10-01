from bcc import BPF

prog='''

#include <linux/skbuff.h>
#include <linux/netdevice.h>

TRACEPOINT_PROBE(net, netif_receive_skb) {
  struct sk_buff *skb = NULL;
  struct net_device *dev = NULL;
  char dev_name[IFNAMSIZ] = {};
  // bpf_probe_read(skb, sizeof(struct sk_buff), args->skbaddr);
  // bpf_probe_read(dev, sizeof(struct net_device), skb->dev);
  // bpf_probe_read(dev_name, IFNAMSIZ, dev->name);

  // bpf_trace_printk("skb: %p, dev: %p, name: %s\\n", skb, dev, dev_name);

  bpf_trace_printk("%p\\n", args->skbaddr);
  return 0;
}

'''

b = BPF(text=prog)

b.trace_print()
