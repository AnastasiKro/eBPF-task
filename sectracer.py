#!/usr/bin/python3

import sys
from bcc import BPF

# BPF program

prog=r"""
struct data_t{
    char buffer[200];
    int uid;
    int f;
};
BPF_RINGBUF_OUTPUT(buffer, 8);

TRACEPOINT_PROBE(syscalls, sys_enter_write) {
    struct data_t event = {};
    bpf_probe_read_user_str(event.buffer, sizeof(event.buffer), args->buf);
    event.uid = bpf_get_current_uid_gid();
    event.f = args->fd;
    buffer.ringbuf_output(&event, sizeof(event), 0);
    return 0;
};
TRACEPOINT_PROBE(syscalls, sys_enter_read) {
    struct data_t event = {};
    bpf_probe_read_user_str(event.buffer, sizeof(event.buffer), args->buf);
    event.uid = bpf_get_current_uid_gid();
    event.f = args->fd;
    buffer.ringbuf_output(&event, sizeof(event), 0);
    return 0;
};
"""
# load BPF program
b = BPF(text=prog)
def callback(ctx, data, size):
    event = b['buffer'].event(data)
    if (len(sys.argv) > 1):
        if (event.uid != int(sys.argv[1])):
            return 0
    st = str(event.buffer)
    a = st.find("SECRET=")
    end = st.find("\\x00")
    if (a!=-1 and end!=-1 and event.f == 1):
        print("Found secret: \42" + st[(a+7):(end-1)] + "\42.")
  
b['buffer'].open_ring_buffer(callback)
try:
    while 1:
        b.ring_buffer_poll()
except KeyboardInterrupt:
    sys.exit()
