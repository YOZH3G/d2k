#!/usr/bin/env python3
"""Отчёт hello-shape-probe.sh: по каждому потоку клиента в hello.pcap — режим
(по lport из fetch.txt), задержка SYN→первый сегмент с данными, размеры первых
сегментов, байт от сервера и вид выхода: «нарезка плана» (первый сегмент не
равен голой голове MSS) или «как есть». Для голой головы — лежат ли в ней SNI и
supported_versions (порядок расширений). Итог по режимам из fetch.txt.
hello-shape-report.py RUN_DIR"""
import collections, os, socket, struct, sys

NAMES = {0: 'sni', 0x2b: 'supported_versions', 0xfe0d: 'ech', 0x33: 'key_share', 0x10: 'alpn'}


def exts(head):
    p = 5 + 4 + 2 + 32
    if len(head) < p + 1: return None
    p += 1 + head[p]
    if len(head) < p + 2: return None
    p += 2 + struct.unpack('!H', head[p:p + 2])[0]
    if len(head) < p + 1: return None
    p += 1 + head[p]
    if len(head) < p + 2: return None
    p += 2
    out = []
    while p + 4 <= len(head):
        t, l = struct.unpack('!HH', head[p:p + 4])
        c = p + 4 + l <= len(head)
        out.append((t, c))
        p += 4 + l
        if not c: break
    return out


def flows(path, ip_t):
    f = open(path, 'rb').read()
    magic, = struct.unpack('<I', f[:4])
    E = '<' if magic in (0xa1b2c3d4, 0xa1b23c4d) else '>'
    lt, = struct.unpack(E + 'I', f[20:24])
    off = 24
    ev = {}
    while off + 16 <= len(f):
        s, us, incl, _ = struct.unpack(E + 'IIII', f[off:off + 16])
        off += 16
        pkt = f[off:off + incl]
        off += incl
        ipb = pkt[(16 if lt == 113 else 14):]
        if len(ipb) < 20 or ipb[0] >> 4 != 4 or ipb[9] != 6: continue
        ihl = (ipb[0] & 15) * 4
        tot = struct.unpack('!H', ipb[2:4])[0]
        src = socket.inet_ntoa(ipb[12:16]); dst = socket.inet_ntoa(ipb[16:20])
        tcp = ipb[ihl:tot]
        sp, dp, seq = struct.unpack('!HHI', tcp[:8])
        flags = tcp[13]; doff = (tcp[12] >> 4) * 4; data = tcp[doff:]
        t = s + us / 1e6
        if dst == ip_t: ev.setdefault(sp, []).append((t, 'C', seq, data, flags))
        elif src == ip_t: ev.setdefault(dp, []).append((t, 'S', seq, data, flags))
    return ev


def main(run):
    ip_t = open(os.path.join(run, 'ip')).read().strip()
    fetch = [l.split() for l in open(os.path.join(run, 'fetch.txt')) if l.strip()]
    lports = {}
    for x in fetch:
        if x[-1].startswith('lport=') and x[-1] != 'lport=-1':
            lports[int(x[-1][6:])] = x[1]
    pcap = os.path.join(run, 'hello.pcap')
    if os.path.isfile(pcap):
        ev = flows(pcap, ip_t)
        print("порт   режим       SYN→1-й сегм. мс  сегменты клиента             сервер Б  вид / голова")
        for p in sorted(ev):
            e = sorted(ev[p], key=lambda x: x[0])
            syn = [x for x in e if x[1] == 'C' and x[4] & 2]
            cdata = [x for x in e if x[1] == 'C' and len(x[3]) > 0]
            sdata = sum(len(x[3]) for x in e if x[1] == 'S')
            if not cdata or not syn: continue
            first = min(cdata, key=lambda x: x[2])
            seqs = collections.OrderedDict()
            for x in sorted(cdata, key=lambda x: x[2]): seqs.setdefault(x[2], x[3])
            sizes = [len(v) for v in list(seqs.values())[:5]]
            head = first[3]
            kind = 'как есть' if head[:1] == b'\x16' and 5 + struct.unpack('!H', head[3:5])[0] > len(head) else 'нарезка плана'
            note = ''
            if kind == 'как есть':
                ex = exts(head) or []
                sni = any(t == 0 and c for t, c in ex); sv = any(t == 0x2b and c for t, c in ex)
                note = f" sni={int(sni)} sv={int(sv)}: " + ' '.join(NAMES.get(t, hex(t)) + ('' if c else '(обрыв)') for t, c in ex)
            print(f"{p:<7}{lports.get(p, '?'):<12}{1000 * (cdata[0][0] - syn[0][0]):>8.1f}          {str(sizes):<29}{sdata:>8}  {kind}{note}")
    tot = collections.OrderedDict()
    for x in fetch:
        m = x[1]; tot.setdefault(m, [0, 0]); tot[m][1] += 1; tot[m][0] += x[3] == 'rc=0'
    print("итог curl: " + ", ".join(f"{m} {o}/{n}" for m, (o, n) in tot.items()))


if __name__ == '__main__':
    main(sys.argv[1])
