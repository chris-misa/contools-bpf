from bcc import BPF

prog='''

#include <linux/skbuff.h>
#include <linux/netdevice.h>

TRACEPOINT_PROBE(net, netif_receive_skb) {
  struct sk_buff *skb = NULL;
  struct net_device *dev = NULL;
  char dev_name[IFNAMSIZ] = {};
  bpf_probe_read(skb, sizeof(struct sk_buff), args->skbaddr);
  // bpf_probe_read(dev, sizeof(struct net_device), skb->dev);
  // bpf_probe_read(dev_name, IFNAMSIZ, dev->name);

  // bpf_trace_printk("skb: %p, dev: %p, name: %s\\n", skb, dev, dev_name);

  bpf_trace_printk("%p\\n", skb);
  return 0;
}

'''

#
# Looks like we can only attach to symbols wrapped in EXPORT_SYMBOL(...)
#
prog2='''
#include <linux/skbuff.h>
#include <linux/netdevice.h>

char outer_dev[] = "eno1d1";

int kprobe__netif_rx(struct pt_regs *ctx, struct sk_buff *skb)
{
    bpf_trace_printk("in netif_rx: name: %s \\n ", skb->dev->name);
    bpf_trace_printk("ifindex: %d \\n ", skb->dev->ifindex);
    return 0;
}

int kprobe__dev_queue_xmit(struct pt_regs *ctx, struct sk_buff *skb)
{
    bpf_trace_printk("in dev_queue_xmit: name: %s \\n ", skb->dev->name);
    bpf_trace_printk("ifindex: %d \\n ", skb->dev->ifindex);
    return 0;
}

'''

b = BPF(text=prog2)

b.trace_print()
