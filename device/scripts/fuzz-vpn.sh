#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
seconds=${1:-60}
[[ "$seconds" =~ ^[0-9]+$ ]] && ((seconds>=1 && seconds<=3600)) || { echo 'seconds must be 1..3600' >&2; exit 2; }
run_dir=$(mktemp -d "${TMPDIR:-/tmp}/meshpn-vpn-fuzz.XXXXXX")
mkdir "$run_dir/corpus"
python3 - "$run_dir/corpus" <<'PY'
import sys,struct
from pathlib import Path
p=Path(sys.argv[1])
for proto,n in [(1,28),(6,44),(17,28)]:
 b=bytearray(n);b[0]=0x45;b[2:4]=struct.pack('!H',n);b[8:10]=bytes([64,proto]);b[12:20]=bytes([10,99,0,2,198,18,0,1])
 if proto==6:b[32]=0x60;b[33]=2;b[40:44]=bytes([2,4,5,180])
 if proto==17:b[24:26]=struct.pack('!H',8)
 for name,data in [('ip',b),('wire',struct.pack('!I',n)+b),('eth',bytes(12)+b'\x08\x00'+b)]:
  (p/f'{proto}-{name}').write_bytes(data)
PY
fuzz_flags=(-fsanitize=fuzzer,address,undefined)
fuzz_link=()
if [[ -n "${LIBFUZZER_ARCHIVE:-}" ]]; then
  fuzz_flags=(-fsanitize=fuzzer-no-link,address,undefined)
  fuzz_link=("$LIBFUZZER_ARCHIVE" -lc++)
fi
"${CC:-clang}" -g -O1 "${fuzz_flags[@]}" -fno-sanitize-recover=undefined \
 -Icomponents/meshvpn_vpn/include tests/fuzz_vpn_packet.c \
 components/meshvpn_vpn/meshvpn_vpn_frame.c components/meshvpn_vpn/meshvpn_vpn_stream.c "${fuzz_link[@]}" -o "$run_dir/fuzz"
echo "Fuzz artifacts: $run_dir"
"$run_dir/fuzz" "$run_dir/corpus" -max_total_time="$seconds" -timeout=5 -max_len=4096 -artifact_prefix="$run_dir/" >"$run_dir/fuzz.log" 2>&1
 tail -n 5 "$run_dir/fuzz.log"
