# RTC Reverse Engineering — /dev/rtc & /dev/rtc0

Reverse engineering of the Linux CMOS Real-Time Clock device (`/dev/rtc0`, symlinked as `/dev/rtc`) on a Debian trixie (6.12.95) x86_64 system.

## Device Overview

| Property | Value |
|----------|-------|
| Device | `/dev/rtc` (symlink → `/dev/rtc0`) |
| Driver | `rtc_cmos` |
| ACPI ID | `PNP0b00` (standard PC CMOS RTC) |
| I/O Ports | `0x70` (register select), `0x71` (data) |
| IRQ | 8 (IR-IO-APIC 8-edge) |
| Major:Minor | 249:0 |
| NVRAM Size | 114 bytes |
| Permissions | root-only (`crw------- root root`) |

## Reverse-Engineering Method

Two access paths were investigated:

1. **Sysfs / NVRAM** — `/sys/class/rtc/rtc0/` and `/sys/devices/pnp0/00:02/cmos_nvram0/nvmem`
   - NVRAM was a stale snapshot, not real-time state
   - 114 bytes total, offset 0x40 read-only, rest writable

2. **Direct I/O via `/dev/port`** — reads/writes CMOS registers directly
   - Provides real-time state
   - User RAM area (0x0E–0x3F) confirmed writable

3. **ioctl interface via `/dev/rtc0`** — `RTC_RD_TIME`, `RTC_ALM_READ`, `RTC_WKALM_RD`, `RTC_IRQP_READ`

## Key Findings

### Time & Alarm

| Register | Value | Interpretation |
|----------|-------|----------------|
| RTC time | 15:07:29 | Current hardware time |
| RTC alarm | 19:22:39 | Alarm set for today |
| Wakealarm | 1795187430 | Fri Nov 20 15:22:30 UTC |

### CMOS Status Registers

| Register | Value | Meaning |
|----------|-------|---------|
| Status A (0x0A) | `0x26` | UIP=0 (updates running), RS=6 → 1024 Hz periodic rate |
| Status B (0x0B) | `0x02` | SET=0 (running), DM=0 (BCD), 24-hour format, DST disabled |
| Status C (0x0C) | `0x50` | PF=1 (periodic flag), AF=1 (alarm flag) |
| Status D (0x0D) | `0x80` | VRT=1 (Valid RAM & Time — battery OK) |

### Working ioctls

| ioctl | Opcode | Status |
|-------|--------|--------|
| `RTC_RD_TIME` | `0x80247009` | ✅ Works |
| `RTC_ALM_READ` | `0x002cf008` | ✅ Works |
| `RTC_WKALM_RD` | `0x00287010` | ✅ Works |
| `RTC_IRQP_READ` | `0x8008700b` | ✅ Returns 1024 Hz |
| `RTC_SET_TIME` | `0x10024700a` | ❌ Inappropriate ioctl |
| `RTC_EPOCH_READ/SET` | `0x002cf00d` / `0x10024700e` | ❌ Not supported |
| `RTC_VL_READ/CLR` | `0x002cf013` / `0x00247014` | ❌ Not supported |
| `RTC_AIE_ON/OFF` | `0x00047001` / `0x00047002` | ❌ Not supported |
| `RTC_UIE_ON/OFF` | `0x00047003` / `0x00047004` | ❌ Not supported |
| `RTC_PIE_ON/OFF` | `0x00047005` / `0x00047006` | ❌ Not supported |

### Alarm Interrupt Verification

When alarm time matches current time **and** AIE (bit 5) is enabled in Status B:
- Status C AF flag sets
- IRQ 8 fires (verified via `/proc/interrupts`)

## Files

| File | Description |
|------|-------------|
| `README.md` | This file |
| `read_rtc_ioctl.py` | Complete ioctl probe script |
| `HYPOTHESES.csv` | Full audit trail of reverse-engineering hypotheses (13 proved) |

## Usage

Read RTC time via ioctl (requires root):

```bash
sudo python3 read_rtc_ioctl.py
```

Read CMOS registers directly via `/dev/port`:

```bash
sudo python3 -c "
# Open /dev/port, write register to 0x70, read data from 0x71
"
```

## Audit Trail

All hypotheses tested during this investigation are recorded in `HYPOTHESES.csv` using the hypothesis-debugging methodology (formulate → test → record conclusion). All 13 hypotheses were proved.

## References

- Linux kernel header: `include/linux/rtc.h`
- Kernel driver: `drivers/rtc/rtc-cmos.c`
- CMOS RTC datasheet: MC146818A / DS12887 compatible register map