#!/usr/bin/env bash
# Regression suite for suno_clip_to_mp3.py
set -u
cd "$(dirname "$0")"
SCRIPT=./suno_clip_to_mp3.py
FIX=/tmp/opencode/sct
pass=0; fail=0

check () {  # name expect_ok url
  local name="$1" expect="$2" url="$3"
  local out; out=$(python3 "$SCRIPT" --url "$url" -o "$FIX/out_$name.mp3" 2>&1 | tr -d '\000')
  if echo "$out" | grep -qE "$expect"; then
    printf '  \033[32mPASS\033[0m  %-18s %s\n' "$name" "$(echo "$out" | grep -oE 'verified: .*' | head -1)"
    pass=$((pass+1))
  else
    printf '  \033[31mFAIL\033[0m  %-18s\n' "$name"
    echo "$out" | grep -E '^\s*\[x\]' | head -3 | sed 's/^/          /'
    fail=$((fail+1))
  fi
}

echo "== container repair paths =="
check good          'playable MP3 written' "file://$FIX/good.m4a"
check pfx_stale     'playable MP3 written' "file://$FIX/pfx_stale.m4a"
check pfx_consistent 'playable MP3 written' "file://$FIX/pfx_consistent.m4a"
check raw_adts      'playable MP3 written' "file://$FIX/raw.m4a"
check raw_mp3       'playable MP3 written' "file://$FIX/rawmp3.m4a"
check mdat_adts     'playable MP3 written' "file://$FIX/fake_mdat_adts.m4a"

echo "== the real clip (encrypted master) =="
for link in \
  'https://d2lwuy8qc234o3.cloudfront.net/1/clip/985f338b-79b2-47f8-8c5f-34eb864a5d0f.m4a' \
  'https://suno.com/song/985f338b-79b2-47f8-8c5f-34eb864a5d0f' \
  'https://suno.com/s/lN26vGvSMqnWMss5' ; do
  out=$(python3 "$SCRIPT" --url "$link" -o "$FIX/out_real.mp3" 2>&1 | tr -d '\000')
  if echo "$out" | grep -q 'playable MP3 written'; then
    printf '  \033[32mPASS\033[0m  %-18s %s\n' "link ok" "$(echo "$out" | grep -oE 'verified: .*' | head -1)"
    pass=$((pass+1))
  else
    printf '  \033[31mFAIL\033[0m  %-18s %s\n' "link ok" "$link"
    fail=$((fail+1))
  fi
done

out=$(python3 "$SCRIPT" --url 'https://d2lwuy8qc234o3.cloudfront.net/1/clip/985f338b-79b2-47f8-8c5f-34eb864a5d0f.m4a' \
      -o "$FIX/out_real.mp3" 2>&1 | tr -d '\000')
if echo "$out" | grep -q 'detected *: ENCRYPTED'; then
  printf '  \033[32mPASS\033[0m  %-18s %s\n' real_clip "detected ENCRYPTED"
  pass=$((pass+1))
else
  printf '  \033[31mFAIL\033[0m  %-18s\n' real_clip; fail=$((fail+1))
fi
if echo "$out" | grep -q 'content key unwrapped via guest-license-token'; then
  printf '  \033[32mPASS\033[0m  %-18s %s\n' rights_fetch "anonymous playback rights granted"
  pass=$((pass+1))
else
  printf '  \033[31mFAIL\033[0m  %-18s\n' rights_fetch; fail=$((fail+1))
fi
if echo "$out" | grep -qi 'falling back to the download API'; then
  printf '  \033[31mFAIL\033[0m  %-18s %s\n' no_quota "must NOT fall back to the quota-counting API"
  fail=$((fail+1))
else
  printf '  \033[32mPASS\033[0m  %-18s %s\n' no_quota "no download quota spent"
  pass=$((pass+1))
fi

echo
echo "  passed: $pass   failed: $fail"
[ "$fail" -eq 0 ]
