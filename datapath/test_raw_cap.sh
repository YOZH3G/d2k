#!/bin/sh
# test_raw_cap.sh — прогон test_raw_cap в своём сетевом пространстве имён.
# Только Linux и root: unshare -n даёт пустое пространство, dummy-интерфейсы
# живут в нём и исчезают с процессом — хост не трогается. Собирает и зовёт
# цель make test-raw-cap-linux (datapath/Makefile).
set -eu
cd "$(dirname "$0")"
[ -x ./test_raw_cap ] || { echo "test_raw_cap не собран: make test-raw-cap-linux" >&2; exit 2; }
exec unshare -n sh -eu -c '
  ip link set lo up
  ip link add d2klow type dummy
  ip link set d2klow mtu 1280 up
  ip link add d2kout type dummy
  ip link set d2kout mtu 1500 up
  ./test_raw_cap d2kout d2klow
'
