# Also read via /dev/rtc0 using the earlier script's RTC_RD_TIME
import os, fcntl, struct
rtc_time_size = 36
fd = os.open('/dev/rtc', os.O_RDONLY)
buf = bytearray(rtc_time_size)
fcntl.ioctl(fd, 0x80247009, buf)  # RTC_RD_TIME
vals = struct.unpack('9i', bytes(buf))
print(f'Kernel RTC time: sec={vals[0]} min={vals[1]} hour={vals[2]} mday={vals[3]} mon={vals[4]} year={vals[5]} wday={vals[6]} yday={vals[7]} isdst={vals[8]}')
