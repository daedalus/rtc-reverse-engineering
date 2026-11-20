#!/usr/bin/env python3
"""
read_rtc_ioctl.py — Complete probe of the Linux RTC character device.

Reverse-engineering companion script for /dev/rtc0 (a.k.a. /dev/rtc).
Tests the full ioctl surface of the rtc_cmos driver and, optionally,
dumps the raw CMOS registers through I/O ports 0x70/0x71.

REQUIRES ROOT (the RTC device node is crw------- root:root,
and /dev/port access is privileged).

Tested on: Debian 13 (trixie), kernel 6.12.95, x86_64
           PNP0b00 CMOS RTC driven by rtc_cmos, IRQ 8.

Usage:
    sudo python3 read_rtc_ioctl.py [--port-dump] [--json]

Options:
    --port-dump   Also dump raw CMOS registers via /dev/port (0x70/0x71)
    --json        Emit machine-readable JSON instead of human text
"""

import argparse
import fcntl
import json
import os
import struct
import sys

RTC_DEV = "/dev/rtc0"

# ---------------------------------------------------------------------------
# ioctl encoding (see include/uapi/asm-generic/ioctl.h)
#   _IOC(dir, type, nr, size) = dir<<30 | type<<8 | nr | size<<16
#   _IOW  = dir 1 (write),  _IOR = dir 2 (read)
# ---------------------------------------------------------------------------
_IOC_WRITE = 1
_IOC_READ = 2


def _ioc(direction, type_char, nr, size):
    return (
        (direction << 30)
        | (ord(type_char) << 8)
        | (nr & 0xFF)
        | ((size & 0x3FFF) << 16)
    )


def _iow(type_char, nr, size):
    return _ioc(_IOC_WRITE, type_char, nr, size)


def _ior(type_char, nr, size):
    return _ioc(_IOC_READ, type_char, nr, size)


# struct rtc_time is 9 ints = 36 bytes (see include/linux/rtc.h)
RTC_TIME_SIZE = struct.calcsize("9i")  # 36
# struct rtc_wkalrm = 2 bytes + struct rtc_time (+ padding) = 40 bytes
WKALRM_SIZE = 40
ULONG_SIZE = struct.calcsize("Q")  # 8

# ---- ioctl numbers --------------------------------------------------------
RTC_AIE_ON = _ioc(_IOC_READ, "p", 0x01, 0)  # _IO
RTC_AIE_OFF = _ioc(_IOC_READ, "p", 0x02, 0)
RTC_UIE_ON = _ioc(_IOC_READ, "p", 0x03, 0)
RTC_UIE_OFF = _ioc(_IOC_READ, "p", 0x04, 0)
RTC_PIE_ON = _ioc(_IOC_READ, "p", 0x05, 0)
RTC_PIE_OFF = _ioc(_IOC_READ, "p", 0x06, 0)
RTC_ALM_SET = _iow("p", 0x07, RTC_TIME_SIZE)
RTC_ALM_READ = _ior("p", 0x08, RTC_TIME_SIZE)
RTC_RD_TIME = _ior("p", 0x09, RTC_TIME_SIZE)
RTC_SET_TIME = _iow("p", 0x0A, RTC_TIME_SIZE)
RTC_IRQP_READ = _ior("p", 0x0B, ULONG_SIZE)
RTC_IRQP_SET = _iow("p", 0x0C, ULONG_SIZE)
RTC_EPOCH_READ = _ior("p", 0x0D, ULONG_SIZE)
RTC_EPOCH_SET = _iow("p", 0x0E, ULONG_SIZE)
RTC_WKALM_SET = _iow("p", 0x0F, WKALRM_SIZE)
RTC_WKALM_RD = _ior("p", 0x10, WKALRM_SIZE)
RTC_PLL_GET = _ior("p", 0x11, 32)
RTC_PLL_SET = _iow("p", 0x12, 32)
RTC_VL_READ = _ior("p", 0x13, 4)
RTC_VL_CLR = _ioc(_IOC_READ, "p", 0x14, 0)

RTC_TIME_FIELDS = (
    "tm_sec",
    "tm_min",
    "tm_hour",
    "tm_mday",
    "tm_mon",
    "tm_year",
    "tm_wday",
    "tm_yday",
    "tm_isdst",
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def open_rtc(flags=os.O_RDONLY):
    try:
        return os.open(RTC_DEV, flags)
    except PermissionError:
        sys.exit(
            f"error: permission denied opening {RTC_DEV}\n"
            "       run this script with sudo (device is root-only)"
        )
    except FileNotFoundError:
        sys.exit(f"error: {RTC_DEV} not found (is the rtc_cmos driver loaded?)")


def unpack_rtc_time(buf):
    return dict(zip(RTC_TIME_FIELDS, struct.unpack("9i", bytes(buf))))


def ioctl_read(fd, request, size):
    """Perform an _IOR ioctl into a bytearray and return the raw bytes."""
    buf = bytearray(size)
    fcntl.ioctl(fd, request, buf)
    return bytes(buf)


def ioctl_read_ulong(fd, request):
    buf = bytearray(ULONG_SIZE)
    fcntl.ioctl(fd, request, buf)
    return struct.unpack("Q", buf)[0]


def probe_ioctl(fd, request, name, size=0):
    """Try an ioctl and report OK / errno, without propagating the error."""
    try:
        if size:
            buf = bytearray(size)
            fcntl.ioctl(fd, request, buf)
            return {"name": name, "ok": True, "errno": None, "data": buf.hex()}
        fcntl.ioctl(fd, request, 0)
        return {"name": name, "ok": True, "errno": None}
    except OSError as exc:
        return {"name": name, "ok": False, "errno": exc.errno, "error": str(exc)}


# ---------------------------------------------------------------------------
# CMOS direct-port access (/dev/port, ports 0x70 = index, 0x71 = data)
# ---------------------------------------------------------------------------
CMOS_INDEX_PORT = 0x70
CMOS_DATA_PORT = 0x71

CMOS_REGISTER_NAMES = {
    0x00: "seconds",
    0x01: "seconds_alarm",
    0x02: "minutes",
    0x03: "minutes_alarm",
    0x04: "hours",
    0x05: "hours_alarm",
    0x06: "day_of_week",
    0x07: "day_of_month",
    0x08: "month",
    0x09: "year",
    0x0A: "status_A",
    0x0B: "status_B",
    0x0C: "status_C",
    0x0D: "status_D",
    0x0E: "diagnostic",
    0x0F: "shutdown",
}


class CmosPort:
    """Read/write CMOS registers directly through /dev/port."""

    def __init__(self):
        self.fd = os.open("/dev/port", os.O_RDWR)

    def _select(self, reg):
        os.lseek(self.fd, CMOS_INDEX_PORT, os.SEEK_SET)
        os.write(self.fd, bytes([reg & 0x7F]))

    def read(self, reg):
        self._select(reg)
        os.lseek(self.fd, CMOS_DATA_PORT, os.SEEK_SET)
        return os.read(self.fd, 1)[0]

    def write(self, reg, value):
        self._select(reg)
        os.lseek(self.fd, CMOS_DATA_PORT, os.SEEK_SET)
        os.write(self.fd, bytes([value & 0xFF]))

    def close(self):
        os.close(self.fd)


def decode_status_a(v):
    return {
        "raw": f"0x{v:02x}",
        "UIP_update_in_progress": (v >> 7) & 1,
        "divider": (v >> 4) & 0x7,
        "rate_select": v & 0xF,
        "periodic_hz": 32768 >> ((v & 0xF) - 1) if (v & 0xF) else 0,
    }


def decode_status_b(v):
    return {
        "raw": f"0x{v:02x}",
        "SET_halt_updates": (v >> 7) & 1,
        "PIE_periodic_int": (v >> 6) & 1,
        "AIE_alarm_int": (v >> 5) & 1,
        "UIE_update_int": (v >> 4) & 1,
        "SQWE_square_wave": (v >> 3) & 1,
        "DM_binary_mode": (v >> 2) & 1,
        "hour_24h": (v >> 1) & 1,
        "DSE_dst_enable": v & 1,
    }


def decode_status_d(v):
    return {
        "raw": f"0x{v:02x}",
        "VRT_valid_ram_and_time": (v >> 7) & 1,
        "battery_ok": bool((v >> 7) & 1),
    }


def dump_cmos(port):
    regs = {}
    for reg in list(range(0x00, 0x10)) + list(range(0x10, 0x40)):
        regs[reg] = port.read(reg)

    result = {
        "registers": {f"0x{reg:02x}": regs[reg] for reg in sorted(regs)},
        "named": {},
        "status": {},
    }

    # Named time/alarm registers (BCD unless DM=1)
    for reg in range(0x00, 0x0E):
        name = CMOS_REGISTER_NAMES.get(reg, f"0x{reg:02x}")
        result["named"][name] = f"0x{regs[reg]:02x}"

    result["status"]["A"] = decode_status_a(regs[0x0A])
    result["status"]["B"] = decode_status_b(regs[0x0B])
    result["status"]["C"] = {
        "raw": f"0x{regs[0x0C]:02x}",
        "IRQF": (regs[0x0C] >> 7) & 1,
        "PF_periodic": (regs[0x0C] >> 6) & 1,
        "AF_alarm": (regs[0x0C] >> 5) & 1,
        "UF_update": (regs[0x0C] >> 4) & 1,
    }
    result["status"]["D"] = decode_status_d(regs[0x0D])

    # Extended NVRAM (0x40-0x7F) — only report non-zero
    ext = {}
    for reg in range(0x40, 0x80):
        val = port.read(reg)
        if val:
            ext[f"0x{reg:02x}"] = f"0x{val:02x}"
    result["extended_nvram_nonzero"] = ext
    return result


def bcd_to_int(b):
    return (b >> 4) * 10 + (b & 0x0F)


# ---------------------------------------------------------------------------
# Main probe
# ---------------------------------------------------------------------------
def run_probe(do_port_dump):
    report = {"device": RTC_DEV, "results": {}}

    fd = open_rtc(os.O_RDONLY)

    # --- time ---------------------------------------------------------------
    raw = ioctl_read(fd, RTC_RD_TIME, RTC_TIME_SIZE)
    report["results"]["time"] = unpack_rtc_time(raw)

    # --- alarm --------------------------------------------------------------
    raw = ioctl_read(fd, RTC_ALM_READ, RTC_TIME_SIZE)
    report["results"]["alarm"] = unpack_rtc_time(raw)

    # --- wake alarm ---------------------------------------------------------
    wraw = ioctl_read(fd, RTC_WKALM_RD, WKALRM_SIZE)
    enabled, pending = wraw[0], wraw[1]
    wtime = dict(zip(RTC_TIME_FIELDS, struct.unpack_from("9i", wraw, 4)))
    report["results"]["wakealarm"] = {
        "enabled": enabled,
        "pending": pending,
        "time": wtime,
    }

    # --- periodic IRQ rate --------------------------------------------------
    try:
        report["results"]["irq_freq_hz"] = ioctl_read_ulong(fd, RTC_IRQP_READ)
    except OSError as exc:
        report["results"]["irq_freq_hz"] = {"error": str(exc), "errno": exc.errno}

    # --- epoch --------------------------------------------------------------
    try:
        report["results"]["epoch"] = ioctl_read_ulong(fd, RTC_EPOCH_READ)
    except OSError as exc:
        report["results"]["epoch"] = {"error": str(exc), "errno": exc.errno}

    # --- voltage low --------------------------------------------------------
    try:
        vlbuf = ioctl_read(fd, RTC_VL_READ, 4)
        flags = struct.unpack("I", vlbuf)[0]
        report["results"]["voltage_low"] = {
            "flags": flags,
            "DATA_INVALID": bool(flags & 0x1),
            "BACKUP_LOW": bool(flags & 0x2),
            "BACKUP_EMPTY": bool(flags & 0x4),
            "ACCURACY_LOW": bool(flags & 0x8),
            "BACKUP_SWITCH": bool(flags & 0x10),
        }
    except OSError as exc:
        report["results"]["voltage_low"] = {"error": str(exc), "errno": exc.errno}

    # --- PLL ----------------------------------------------------------------
    try:
        pll = ioctl_read(fd, RTC_PLL_GET, 32)
        report["results"]["pll_get"] = pll.hex()
    except OSError as exc:
        report["results"]["pll_get"] = {"error": str(exc), "errno": exc.errno}

    os.close(fd)

    # --- enable-only probes (non-destructive, expected to be rejected) ------
    fd = open_rtc(os.O_RDONLY)
    probes = []
    for name, req in (
        ("RTC_AIE_ON", RTC_AIE_ON),
        ("RTC_UIE_ON", RTC_UIE_ON),
        ("RTC_PIE_ON", RTC_PIE_ON),
    ):
        probes.append(probe_ioctl(fd, req, name))
    os.close(fd)
    report["results"]["interrupt_enable_probes"] = probes

    # --- SET probes: only test errno, never actually commit a change --------
    # We deliberately do NOT call RTC_SET_TIME / RTC_ALM_SET / RTC_WKALM_SET
    # because they mutate hardware. Instead we document that the driver
    # returns ENOTTY for RTC_SET_TIME on this platform (see README).

    # --- direct CMOS dump ---------------------------------------------------
    if do_port_dump:
        try:
            port = CmosPort()
            report["results"]["cmos"] = dump_cmos(port)
            port.close()
        except PermissionError:
            report["results"]["cmos"] = {"error": "permission denied on /dev/port"}
        except FileNotFoundError:
            report["results"]["cmos"] = {"error": "/dev/port not available"}

    return report


def print_human(report):
    r = report["results"]
    print("=" * 68)
    print(f" RTC probe: {report['device']}")
    print("=" * 68)

    t = r["time"]
    print(
        f"\n[time]      {t['tm_year'] + 1900:04d}-{t['tm_mon'] + 1:02d}-"
        f"{t['tm_mday']:02d} {t['tm_hour']:02d}:{t['tm_min']:02d}:{t['tm_sec']:02d}"
        f"  (year field={t['tm_year']}, mon field={t['tm_mon']})"
    )

    a = r["alarm"]
    print(
        f"[alarm]     {a['tm_year'] + 1900:04d}-{a['tm_mon'] + 1:02d}-"
        f"{a['tm_mday']:02d} {a['tm_hour']:02d}:{a['tm_min']:02d}:{a['tm_sec']:02d}"
    )

    w = r["wakealarm"]
    wt = w["time"]
    print(
        f"[wakealarm] enabled={w['enabled']} pending={w['pending']} "
        f"time={wt['tm_hour']:02d}:{wt['tm_min']:02d}:{wt['tm_sec']:02d}"
    )

    freq = r.get("irq_freq_hz")
    print(f"[irq freq]  {freq if not isinstance(freq, dict) else freq.get('error')}")

    ep = r.get("epoch")
    print(f"[epoch]     {ep if not isinstance(ep, dict) else ep.get('error')}")

    vl = r.get("voltage_low")
    if isinstance(vl, dict) and "flags" in vl:
        print(f"[voltage]   flags=0x{vl['flags']:x} battery_ok={not vl['BACKUP_LOW']}")
    else:
        print(f"[voltage]   {vl.get('error') if isinstance(vl, dict) else vl}")

    pll = r.get("pll_get")
    print(f"[pll]       {pll if not isinstance(pll, dict) else pll.get('error')}")

    print("\n[interrupt enable probes]")
    for p in r["interrupt_enable_probes"]:
        status = "OK" if p["ok"] else f"errno {p['errno']} ({p.get('error', '')})"
        print(f"  {p['name']:<12} {status}")

    if "cmos" in r:
        cmos = r["cmos"]
        if "error" in cmos:
            print(f"\n[cmos] {cmos['error']}")
        else:
            print("\n[cmos status registers]")
            for key in ("A", "B", "C", "D"):
                print(f"  Status {key}: {cmos['status'][key]}")
            if cmos["extended_nvram_nonzero"]:
                print("\n[extended NVRAM non-zero]")
                for reg, val in cmos["extended_nvram_nonzero"].items():
                    print(f"  {reg}: {val}")

    print()


def main():
    parser = argparse.ArgumentParser(description="Probe the Linux RTC device.")
    parser.add_argument(
        "--port-dump",
        action="store_true",
        help="also dump raw CMOS registers via /dev/port (0x70/0x71)",
    )
    parser.add_argument(
        "--json", action="store_true", help="emit JSON instead of human text"
    )
    args = parser.parse_args()

    if os.geteuid() != 0:
        print(
            "warning: not running as root — ioctl access will likely fail\n",
            file=sys.stderr,
        )

    report = run_probe(args.port_dump)

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print_human(report)


if __name__ == "__main__":
    main()