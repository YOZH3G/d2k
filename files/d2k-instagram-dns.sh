#!/bin/sh
# Resolve Instagram/fbcdn/WhatsApp Web A records through d2k's own C resolver
# on the VPS (d2k-enroll POST /resolve) and manage only the exact static DNS
# pairs owned by this D2K installation.
set -eu
export PATH="${D2K_STUB_PATH:+$D2K_STUB_PATH:}/opt/sbin:/opt/bin:/sbin:/usr/sbin:/bin:/usr/bin"
DIR=${D2K_DIR:-/opt/d2k}
META_RANGES=${D2K_META_RANGES:-$DIR/files/meta-ranges.txt}
MANIFEST=${D2K_INSTAGRAM_MANIFEST:-$DIR/state/instagram-ip-hosts.tsv}
LOG=${D2K_INSTAGRAM_LOG:-$DIR/log/instagram-dns.log}
RELAY_URL=${D2K_RELAY_URL:-https://213.176.74.63.nip.io:9443/resolve}
# The only list: d2ktg --check-instagram-ip and the VPS allowlist carry the
# same names (scripts/test-instagram-dns.sh compares them).
HOSTS='instagram.com www.instagram.com graph.instagram.com api.instagram.com i.instagram.com instagram.c10r.instagram.com static.cdninstagram.com scontent.cdninstagram.com static.xx.fbcdn.net scontent.xx.fbcdn.net web.whatsapp.com www.whatsapp.com scontent.whatsapp.net graph.whatsapp.com v.whatsapp.com'
mkdir -p "$(dirname "$LOG")" "$(dirname "$MANIFEST")" 2>/dev/null || true
log() { printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$1" >>"$LOG"; }
mark_refresh_success() {
    state=${D2K_INSTAGRAM_SCHED_STATE:-$DIR/state/instagram-dns-last-success}
    tmp="$state.new.$$"
    if printf '%s\n' "$(date +%Y-%m-%d)" > "$tmp" && mv -f "$tmp" "$state"; then
        :
    else
        rm -f "$tmp"
        log 'не удалось записать дату успешного обновления; планировщик может повторить его сегодня'
    fi
}
managed_host() { case " $HOSTS " in *" $1 "*) return 0;; *) return 1;; esac; }
valid_ipv4() {
    case "$1" in *[!0-9.]*|*..*|.*|*.) return 1;; esac
    awk -F. 'NF==4 {for(i=1;i<=4;i++) if($i !~ /^[0-9]+$/ || $i>255) exit 1; exit 0} {exit 1}' <<EOF_IP
$1
EOF_IP
}
is_meta_ip() {
    valid_ipv4 "$1" || return 1
    awk -v ip="$1" 'function n(s,a){split(s,a,".");return ((a[1]*256+a[2])*256+a[3])*256+a[4]} BEGIN{v=n(ip);ok=0} /^[[:space:]]*#/||/^[[:space:]]*$/ {next} {split($0,p,"/");if(p[2]!~/^[0-9]+$/||p[2]<0||p[2]>32)next;s=2^(32-p[2]);if(int(v/s)==int(n(p[1])/s))ok=1} END{exit !ok}' "$META_RANGES" 2>/dev/null
}
running_config() { LD_LIBRARY_PATH='' ndmc -c 'show running-config' 2>/dev/null; }
record_exists() {
    current=$(running_config) || return 2
    printf '%s\n' "$current" | awk -v h="$1" -v ip="$2" \
        '$1=="ip"&&$2=="host"&&$3==h&&$4==ip {f=1} END{exit !f}'
}
remove_owned() {
    [ -s "$MANIFEST" ] || { rm -f "$MANIFEST"; log 'нет D2K-owned DNS-записей Instagram/WhatsApp'; return 0; }
    command -v ndmc >/dev/null 2>&1 || { log 'ndmc отсутствует; manifest оставлен'; return 1; }
    while read -r host ip _extra; do
        [ -n "${host:-}" ] && [ -n "${ip:-}" ] || continue
        if ! managed_host "$host" || ! valid_ipv4 "$ip"; then
            log 'игнорирую некорректную строку manifest'
            continue
        fi
        if record_exists "$host" "$ip"; then
            LD_LIBRARY_PATH='' ndmc -c "no ip host $host $ip" >/dev/null 2>&1 || { log "ошибка удаления $host $ip"; return 1; }
            log "удалена D2K-запись $host $ip"
        else
            rc=$?
            [ "$rc" = 1 ] || { log "не удалось проверить NDM перед удалением $host $ip"; return 1; }
        fi
    done < "$MANIFEST"
    if ! LD_LIBRARY_PATH='' ndmc -c 'system configuration save' >/dev/null 2>&1; then
        log 'не удалось сохранить конфигурацию NDM; manifest оставлен для повтора'
        return 1
    fi
    rm -f "$MANIFEST"
}
refresh() {
    if ! command -v ndmc >/dev/null 2>&1; then log 'ndmc отсутствует — пропускаю (не Keenetic)'; return 0; fi
    [ -s "$META_RANGES" ] || { log "нет списка диапазонов Meta: $META_RANGES"; return 1; }
    command -v d2ktg >/dev/null 2>&1 || { log 'нет C-инструмента проверки адресов d2ktg'; return 1; }
    ca_bundle=${D2K_IP_CA_BUNDLE:-/opt/etc/ssl/certs/ca-certificates.crt}
    [ -r "$ca_bundle" ] || ca_bundle=/etc/ssl/certs/ca-certificates.crt
    [ -r "$ca_bundle" ] || { log 'нет системных доверенных CA; установите ca-bundle'; return 1; }
    # No credential: the VPS answers public DNS data for this fixed list only.
    RELAY_AUTHORITY=${RELAY_URL#*://}; RELAY_AUTHORITY=${RELAY_AUTHORITY%%/*}
    RELAY_HOST=${RELAY_AUTHORITY%%:*}
    RELAY_PORT=443
    case "$RELAY_AUTHORITY" in *:*) RELAY_PORT=${RELAY_AUTHORITY##*:};; esac
    RESOLVE_IP=
    case "$RELAY_HOST" in *.nip.io) _nip=${RELAY_HOST%.nip.io}; case "$_nip" in *[!0-9.]*|*..*|.*|*.) ;; *.*.*.*.*) ;; *.*.*.*) RESOLVE_IP=$_nip;; esac;; esac
    body='{"hosts":['; first=1
    for host in $HOSTS; do [ "$first" = 1 ] || body="$body,"; body="$body\"$host\""; first=0; done
    body="$body]}"
    attempts=${D2K_RESOLVE_ATTEMPTS:-3}
    attempt=1
    response=
    while [ "$attempt" -le "$attempts" ]; do
        if [ -n "$RESOLVE_IP" ]; then
            response=$(curl -fsS --connect-timeout "${D2K_RESOLVE_CONNECT_TIMEOUT:-5}" \
                --max-time "${D2K_RESOLVE_TIMEOUT:-15}" --resolve "$RELAY_HOST:$RELAY_PORT:$RESOLVE_IP" \
                -X POST "$RELAY_URL" -H 'Content-Type: application/json' \
                --data "$body" 2>>"$LOG") && break
        else
            response=$(curl -fsS --connect-timeout "${D2K_RESOLVE_CONNECT_TIMEOUT:-5}" \
                --max-time "${D2K_RESOLVE_TIMEOUT:-15}" -X POST "$RELAY_URL" \
                -H 'Content-Type: application/json' \
                --data "$body" 2>>"$LOG") && break
        fi
        log "VPS /resolve: попытка $attempt/$attempts не удалась"
        attempt=$((attempt + 1))
        [ "$attempt" -le "$attempts" ] && sleep "${D2K_RESOLVE_RETRY_DELAY:-3}"
    done
    [ -n "$response" ] || { log 'VPS /resolve не ответил после повторов; текущие DNS-записи не изменены'; return 1; }
    log "VPS /resolve ответил (попытка $attempt/$attempts)"
    printf '%s' "$response" | grep -q '"results"' || { log 'ответ VPS не содержит results'; return 1; }
    parsed=$(printf '%s' "$response" | sed -e 's/.*"results":{//' -e 's/}}$//' -e 's/\],/\n/g' -e 's/\]$//' | awk '{n1=index($0,"\"");if(!n1)next;r=substr($0,n1+1);n2=index(r,"\"");if(!n2)next;h=substr(r,1,n2-1);ips=substr(r,n2+1);gsub(/[^0-9.,]/,"",ips);n=split(ips,a,",");for(i=1;i<=n;i++)if(a[i]~/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/)print h" "a[i]}')
    [ -n "$parsed" ] || { log 'не удалось разобрать ответ VPS'; return 1; }
    filtered=
    for host in $HOSTS; do
        tried=0
        kept=0
        for ip in $(printf '%s\n' "$parsed" | awk -v h="$host" '$1==h{print $2}' | head -8); do
            [ "$tried" -lt 4 ] || break
            tried=$((tried + 1))
            is_meta_ip "$ip" || { log "отброшен адрес вне диапазонов Meta: $host $ip"; continue; }
            probe_attempt=1
            edge_ok=0
            probe_attempts=${D2K_IP_PROBE_ATTEMPTS:-2}
            while [ "$probe_attempt" -le "$probe_attempts" ]; do
                # DNS pinning checks edge reachability, not whether Instagram's
                # SNI is already unblocked. The C control verifies the real
                # Meta certificate with neutral wire SNI, without HTTP traffic.
                if d2ktg --check-instagram-ip "$host" "$ip" "$ca_bundle" >>"$LOG" 2>&1; then
                    edge_ok=1
                    break
                fi
                if [ "$probe_attempt" -lt "$probe_attempts" ]; then
                    log "повтор TLS-пробы $probe_attempt/$probe_attempts: $host $ip"
                    sleep "${D2K_IP_PROBE_RETRY_DELAY:-1}"
                fi
                probe_attempt=$((probe_attempt + 1))
            done
            if [ "$edge_ok" = 1 ]; then
                filtered="${filtered}${host} ${ip}\n"
                kept=$((kept + 1))
                [ "$kept" -lt 2 ] || break
            else
                log "адрес не прошёл TLS-проверку доступности и сертификата Meta: $host $ip"
            fi
        done
    done
    [ -n "$filtered" ] || { log 'VPS ответил, но нет адресов с доступным и подлинным TLS-сервисом Meta; DNS не изменён'; return 1; }
    if ! printf '%b' "$filtered" | awk '$1=="instagram.com" {ok=1} END{exit !ok}'; then
        log 'VPS не дал ни одного доступного адреса instagram.com; остальные DNS-записи не изменены'
        return 1
    fi
    next="$MANIFEST.new.$$"; : > "$next"
    if [ -f "$MANIFEST" ]; then
        while read -r host ip _extra; do [ -n "${host:-}" ] && [ -n "${ip:-}" ] || continue; managed_host "$host" && valid_ipv4 "$ip" && printf '%s %s\n' "$host" "$ip" >> "$next"; done < "$MANIFEST"
    fi
    add_failed=0
    for host in $HOSTS; do
        for ip in $(printf '%b' "$filtered" | awk -v h="$host" '$1==h{print $2}' | sort -u); do
            # Existing records remain user-owned unless our manifest already claims them.
            if record_exists "$host" "$ip"; then
                continue
            else
                rc=$?
                [ "$rc" = 1 ] || { rm -f "$next"; log "не удалось проверить NDM перед добавлением $host $ip"; return 1; }
            fi
            # Claim the absent pair before adding it: a refresh stopped at any
            # point (service stop, uninstall) still leaves it removable, and
            # remove skips a claimed pair that NDM never received.
            printf '%s %s\n' "$host" "$ip" >> "$MANIFEST"
            if LD_LIBRARY_PATH='' ndmc -c "ip host $host $ip" >/dev/null 2>&1; then
                printf '%s %s\n' "$host" "$ip" >> "$next"; log "добавлена D2K-запись $host $ip"
            else add_failed=1; log "ошибка добавления $host $ip"; fi
        done
    done
    if [ "$add_failed" = 1 ]; then
        # Remember any partial additions so uninstall still owns them, but
        # never retire previous pins when replacement failed.
        sort -u "$next" > "$MANIFEST"; rm -f "$next"
        LD_LIBRARY_PATH='' ndmc -c 'system configuration save' >/dev/null 2>&1 || true
        log 'NDM не принял новые записи; прежние адреса сохранены, обновление не завершено'
        return 1
    fi
    # Replace stale pairs owned by D2K only after this host has at least one
    # freshly probed address installed. A failed/empty host probe keeps its
    # previous working pins; unrelated user-owned records are never touched.
    if [ -f "$MANIFEST" ]; then
        stale_removed=0
        while read -r host ip _extra; do
            [ -n "${host:-}" ] && [ -n "${ip:-}" ] || continue
            if ! managed_host "$host"; then continue; fi
            if ! valid_ipv4 "$ip"; then continue; fi
            fresh=$(printf '%b' "$filtered" | awk -v h="$host" '$1==h{print $2}' | tr '\n' ' ')
            [ -n "$fresh" ] || continue
            case " $fresh " in *" $ip "*) continue;; esac
            if record_exists "$host" "$ip"; then
                if LD_LIBRARY_PATH='' ndmc -c "no ip host $host $ip" >/dev/null 2>&1; then
                    log "удалена устаревшая D2K-запись $host $ip"
                    stale_removed=1
                else
                    rm -f "$next"; log "ошибка удаления устаревшей записи $host $ip"; return 1
                fi
            else
                rc=$?
                [ "$rc" = 1 ] || { rm -f "$next"; log "не удалось проверить NDM перед заменой $host $ip"; return 1; }
                stale_removed=1
            fi
        done < "$MANIFEST"
        if [ "$stale_removed" = 1 ]; then
            kept="$next.kept"
            : > "$kept"
            while read -r host ip _extra; do
                [ -n "${host:-}" ] && [ -n "${ip:-}" ] || continue
                fresh=$(printf '%b' "$filtered" | awk -v h="$host" '$1==h{print $2}' | tr '\n' ' ')
                if [ -n "$fresh" ]; then case " $fresh " in *" $ip "*) :;; *) continue;; esac; fi
                printf '%s %s\n' "$host" "$ip" >> "$kept"
            done < "$next"
            mv -f "$kept" "$next"
        fi
    fi
    sort -u "$next" > "$next.sorted"; mv -f "$next.sorted" "$MANIFEST"; rm -f "$next"
    if ! LD_LIBRARY_PATH='' ndmc -c 'system configuration save' >/dev/null 2>&1; then
        log 'не удалось сохранить конфигурацию NDM'
        return 1
    fi
    log 'обновление DNS Instagram/WhatsApp завершено'
    mark_refresh_success
}
case "${1:-}" in refresh) refresh;; remove) remove_owned;; *) echo "usage: $0 refresh|remove" >&2; exit 2;; esac
