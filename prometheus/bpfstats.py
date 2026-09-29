"""
Minimal reader for per-program eBPF run-time statistics via the bpf(2) syscall.

falcon-sensor-bpf (and osquery's BPF publisher) attach programs to syscalls,
tracepoints and LSM hooks. Those programs run in the context of whatever process
triggered the event, so their cost is charged to that process's *system* time and
is invisible per-sensor in /proc. The kernel does expose it, though, once
run-time stats are enabled: each program then carries run_time_ns and run_cnt.

This module enables the stats (holding the fd so they auto-disable when the
exporter exits) and iterates programs without depending on bpftool.

Requires CAP_BPF/CAP_SYS_ADMIN (i.e. root, which the systemd unit provides).
"""

import ctypes
import ctypes.util
import os
import platform
import struct

# bpf(2) command numbers (uapi/linux/bpf.h)
BPF_PROG_GET_NEXT_ID = 11
BPF_PROG_GET_FD_BY_ID = 13
BPF_OBJ_GET_INFO_BY_FD = 15
BPF_ENABLE_STATS = 32

BPF_STATS_RUN_TIME = 0

# __NR_bpf per architecture
_BPF_SYSCALL = {
    "x86_64": 321,
    "aarch64": 280,
    "ppc64le": 361,
    "s390x": 351,
}

# Stable byte offsets into struct bpf_prog_info. The struct is append-only, so
# these hold across kernel versions (fields exist since Linux 5.1).
_OFF_TYPE = 0
_OFF_ID = 4
_OFF_TAG = 8  # 8 bytes
_OFF_NAME = 64  # 16 bytes
_OFF_RUN_TIME_NS = 192
_OFF_RUN_CNT = 200
_INFO_SIZE = 256


_libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6", use_errno=True)
_libc.syscall.restype = ctypes.c_long


def _bpf(cmd, attr):
    nr = _BPF_SYSCALL.get(platform.machine())
    if nr is None:
        return -1
    ctypes.set_errno(0)
    return _libc.syscall(
        ctypes.c_long(nr),
        ctypes.c_long(cmd),
        ctypes.cast(attr, ctypes.c_void_p),
        ctypes.c_long(len(attr)),
    )


def enable_stats():
    """
    Turn on BPF run-time accounting for the lifetime of the returned fd.

    Returns the fd (keep a reference to it), or None if unavailable.
    """
    attr = ctypes.create_string_buffer(struct.pack("=I", BPF_STATS_RUN_TIME))
    fd = _bpf(BPF_ENABLE_STATS, attr)
    if fd < 0:
        return None
    return fd


def iter_progs():
    """
    Yield a dict per loaded eBPF program.

    Keys: id, type, name, tag, run_time_ns, run_cnt. run_time_ns/run_cnt are
    zero unless stats are enabled (see enable_stats()).
    """
    start_id = 0
    while True:
        attr = ctypes.create_string_buffer(struct.pack("=III", start_id, 0, 0))
        if _bpf(BPF_PROG_GET_NEXT_ID, attr) < 0:
            break  # ENOENT: no more programs
        next_id = struct.unpack_from("=I", attr, 4)[0]
        start_id = next_id

        attr = ctypes.create_string_buffer(struct.pack("=III", next_id, 0, 0))
        fd = _bpf(BPF_PROG_GET_FD_BY_ID, attr)
        if fd < 0:
            continue  # program vanished or not visible

        info = ctypes.create_string_buffer(_INFO_SIZE)
        attr = ctypes.create_string_buffer(
            struct.pack("=IIQ", fd, _INFO_SIZE, ctypes.addressof(info))
        )
        ret = _bpf(BPF_OBJ_GET_INFO_BY_FD, attr)
        os.close(fd)
        if ret < 0:
            continue

        raw = info.raw
        name = raw[_OFF_NAME : _OFF_NAME + 16].split(b"\0", 1)[0]
        tag = raw[_OFF_TAG : _OFF_TAG + 8]
        yield {
            "id": struct.unpack_from("=I", raw, _OFF_ID)[0],
            "type": struct.unpack_from("=I", raw, _OFF_TYPE)[0],
            "name": name.decode("ascii", "replace") or f"prog{next_id}",
            "tag": tag.hex(),
            "run_time_ns": struct.unpack_from("=Q", raw, _OFF_RUN_TIME_NS)[0],
            "run_cnt": struct.unpack_from("=Q", raw, _OFF_RUN_CNT)[0],
        }
