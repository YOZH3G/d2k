#!/bin/sh
# lab-update.sh — СКВОЗНАЯ ЛАБОРАТОРИЯ АВТООБНОВЛЕНИЙ, В КОНТЕЙНЕРАХ, БЕЗ РОУТЕРА.
#
# Гарантии:
#   * частный /opt: каждая проверка идёт в своём контейнере, созданном из
#     снимка настоящей плоской установки A, переведённой подписанным
#     bootstrap-ом в управляемую; контейнер удаляется после прогона;
#   * частный сетевой namespace: `--network none`; в нём только loopback,
#     dummy-интерфейс «LAN» и собственный HTTPS-feed на 127.0.0.1 с
#     одноразовым ТЕСТОВЫМ ключом подписи и ТЕСТОВЫМ CA; релей Telegram закрыт;
#   * никакого SSH, доступа к роутеру, к хостовым /opt, службам, правилам
#     netfilter или производственным ключам; ничего не публикуется.
#
# Что здесь настоящее: бинарники выпусков всех ролей, S98/S99, адаптер и
# супервизор, netfilter/ipset/NFQUEUE ядра Linux, окно здоровья 120 с по
# CLOCK_MONOTONIC, HTTPS/подписи/хеши/anti-replay.
# Что подменено, и это названо в summary.json: источник сведений о
# синхронизации часов (seccomp в update/tests/fault_matrix.c — Docker-VM не
# считает часы синхронизированными, а менять их запрещено); «перезагрузка» —
# SIGKILL всех процессов установки плюс сброс netfilter и /tmp, НЕ потеря
# питания на флеш-памяти; TZ подбирается через /etc/TZ, часы не трогаются.
#
# Фикстуры: D2K_LAB_FIXTURES=каталог, подготовленный
# `python3 update/tests/lab_fixtures.py` (выпуски A и B на девять ABI с
# receipts/gates и подписями; A — с плоской установкой и lab-bootstrap).
# Без переменной лаборатория собирает оба выпуска сама из чистого клона HEAD;
# для этого нужны DEPS_PROVENANCE, ZIG и ZIG_MIPS64EL (см. scripts/build-router.sh).
#
# По умолчанию — четыре основных сценария: подписанное обновление A->B
# (окно здоровья 120 с, отказ отката на выпуск без своего обновлятора,
# перезагрузка), сломанный B откатывается на A, обрыв питания во время
# проверки B, кончившееся место во время загрузки и остановки.
#
# Выход: ненулевой, если хоть одна строка выбранных групп не PASS
# (FAIL, пропуск, тайм-аут). Машинный итог —
# $D2K_LAB_OUT/summary.json (по умолчанию build/lab-update/<дата>/), отдельно
# от stdout, без секретов; сырые журналы и свидетельства рядом в evidence/.
#
# Переменные: D2K_LAB_JOBS (параллельных контейнеров, по умолчанию 4),
# D2K_LAB_GROUPS (группы через запятую или all — вся матрица задачи 11 вместе
# с lab-install.sh/check_firewall.sh; группы сверх основных написаны, но не
# все доведены), D2K_LAB_SKIP_INSTALL_LABS=1 (при all не запускать
# lab-install.sh/check_firewall.sh), D2K_LAB_KEEP=1 (оставить контейнеры и
# образ для осмотра), D2K_LAB_BOOTLOG=1 (вывод супервизора обновлений в
# evidence/<группа>-boot.log).
set -eu
HERE=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH='' cd -- "$HERE/.." && pwd)
IMAGE=${D2K_LAB_IMAGE:-d2k-update-lab:t11}
OUT=${D2K_LAB_OUT:-"$ROOT/build/lab-update/$(date +%Y%m%d-%H%M%S)"}
mkdir -p "$OUT"

docker info >/dev/null 2>&1 || { echo "lab-update.sh: нужен запущенный Docker" >&2; exit 3; }
if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    # Единственный шаг с сетью: сборка образа с ipset/curl/strace поверх
    # лабораторного образа. Сами проверки идут с --network none.
    docker image inspect d2k-update-lab:bookworm >/dev/null 2>&1 || { echo "lab-update.sh: нет образа d2k-update-lab:bookworm" >&2; exit 3; }
    TMPD=$(mktemp -d)
    printf 'FROM d2k-update-lab:bookworm\nRUN apt-get update -qq && apt-get install -y -qq --no-install-recommends ipset curl strace procps kmod && rm -rf /var/lib/apt/lists/*\n' > "$TMPD/Dockerfile"
    docker build -q -t "$IMAGE" "$TMPD" >/dev/null || { echo "lab-update.sh: не собрать образ $IMAGE" >&2; rm -rf "$TMPD"; exit 3; }
    rm -rf "$TMPD"
fi

FIXTURES=${D2K_LAB_FIXTURES:-}
if [ -z "$FIXTURES" ]; then
    : "${DEPS_PROVENANCE:?lab-update.sh: без D2K_LAB_FIXTURES нужен DEPS_PROVENANCE}"
    : "${ZIG:?lab-update.sh: нужен ZIG}"; : "${ZIG_MIPS64EL:?lab-update.sh: нужен ZIG_MIPS64EL}"
    FIXTURES="$OUT/fixtures"
    HEAD=$(git -C "$ROOT" rev-parse HEAD)
    SHORT=$(git -C "$ROOT" rev-parse --short=12 HEAD)
    python3 "$ROOT/update/tests/lab_fixtures.py" build --repo "$ROOT" --commit "$HEAD" --id "lab-$SHORT-A" --out "$FIXTURES" \
        --deps "$DEPS_PROVENANCE" --zig "$ZIG" --zig-mips64el "$ZIG_MIPS64EL" --bootstrap || exit 3
    python3 "$ROOT/update/tests/lab_fixtures.py" build --repo "$ROOT" --commit "$HEAD" --id "lab-$SHORT-B" --out "$FIXTURES" \
        --deps "$DEPS_PROVENANCE" --zig "$ZIG" --zig-mips64el "$ZIG_MIPS64EL" || exit 3
    printf '{"A": "lab-%s-A", "B": "lab-%s-B"}\n' "$SHORT" "$SHORT" > "$FIXTURES/fixtures.json"
fi
[ -f "$FIXTURES/fixtures.json" ] || { echo "lab-update.sh: в $FIXTURES нет fixtures.json" >&2; exit 3; }

set -- --repo "$ROOT" --fixtures "$FIXTURES" --out "$OUT" --image "$IMAGE" --jobs "${D2K_LAB_JOBS:-4}"
[ -z "${D2K_LAB_GROUPS:-}" ] || set -- "$@" --groups "$D2K_LAB_GROUPS"
[ "${D2K_LAB_SKIP_INSTALL_LABS:-0}" = 0 ] || set -- "$@" --skip-install-labs
exec python3 "$ROOT/update/tests/lab_update.py" orchestrate "$@"
