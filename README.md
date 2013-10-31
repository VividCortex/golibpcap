# golibpcap

This is a fork of the https://code.google.com/p/golibpcap/ project.

## Notes
- When building under Linux, you'll have to copy `golibpcap/pcap/libpcap.a` to `/tmp/usr/lib/` for cgo. `libpcap.a` was built using 64-bit CentOS 5.9.

- When building under FreeBSD, you'll have to copy `golibpcap/pcap/libpcap_freebsd.a` to `/tmp/usr/lib` for cgo. `libpcap_freebsd.a` was built using 64-bit FreeBSD 9.2-RELEASE.
