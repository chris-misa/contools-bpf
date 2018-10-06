#!/usr/bin/python

from bcc import BPF
import ctypes as ct
import sys
import signal
import time

USAGE="latency.py <bpf program> <outer device index> <inner device index>"

if len(sys.argv) != 4:
    print(USAGE)
    sys.exit(1)

prog = None

with open(sys.argv[1], "r") as fp:
    prog = fp.read();

if prog is None:
    print("Failed to load program: " + sys.argv[1])
    sys.exit(1)

prog = prog.replace('OUTER_DEV_NAME', '"' + sys.argv[2] + '"')
prog = prog.replace('INNER_DEV_NAME', '"' + sys.argv[3] + '"')

b = BPF(text=prog)

# b.attach_kprobe(event="__netif_receive_skb_core", fn_name="do_recv")
# b.attach_kprobe(event="dev_queue_xmit", fn_name="do_send")

class Latency(ct.Structure):
    _fields_ = [("ts", ct.c_ulonglong),
                ("ns", ct.c_ulonglong),
                ("dir", ct.c_ulong)]


in_flight = False
send_lat = 0
def print_event(cpu, data, size):
    global in_flight, send_lat
    event = ct.cast(data, ct.POINTER(Latency)).contents
    if in_flight and event.dir == 2:
        sys.stdout.write("[%f] rtt raw_latency: %d, events_overhead: %d, end\n" \
                % (time.time(), float(event.ns + send_lat) / 1000.0, 0))
        in_flight = False
        send_lat = 0
    elif event.dir == 1:
        in_flight = True
        send_lat = event.ns

def do_exit(signum, frame):
    sys.stdout.flush()
    sys.exit(0)

def main():
    b["events"].open_perf_buffer(print_event)

    sys.stdout.write("Watching for latencies\n")

    while 1:
        b.perf_buffer_poll()

if __name__ == '__main__':
    signal.signal(signal.SIGINT, do_exit)
    main()



