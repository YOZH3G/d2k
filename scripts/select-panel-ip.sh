#!/bin/sh
# Read `ip -4 -o addr show scope global` and print one safe LAN bind address.
# Prefer Keenetic's primary LAN bridge; otherwise use the first RFC1918 address.
awk '
function private(ip, n, octet) {
    n = split(ip, octet, ".")
    if (n != 4) return 0
    if (octet[1] == 10) return 1
    if (octet[1] == 192 && octet[2] == 168) return 1
    if (octet[1] == 172 && octet[2] >= 16 && octet[2] <= 31) return 1
    return 0
}
{
    iface = $2
    for (i = 1; i < NF; i++) {
        if ($i == "inet") {
            split($(i + 1), address, "/")
            ip = address[1]
            if (private(ip)) {
                if (iface == "br0" || iface == "br-lan" || iface ~ /^lan[0-9]*$/) {
                    print ip
                    selected = 1
                    exit
                }
                if (fallback == "") fallback = ip
            }
            break
        }
    }
}
END {
    if (!selected && fallback != "") print fallback
}
'
