#!/usr/bin/env bash
# Fails when a symbol an argument file asks for is missing from what jextract generated: jextract leaves out a name it
# does not find without a word. For the missing names it prints what jextract's parser saw of them (--dump-includes),
# which tells a name the headers do not declare from one the parser dropped.
#
# Usage: check.sh <argument file> <output directory> <jextract launcher> <header>
set -euo pipefail

arguments=$1
output=$2
jextract=$3
header=$4

missing=()
kind=""
while IFS= read -r line || [ -n "$line" ]; do
  line=${line%$'\r'}
  if [ -n "$kind" ]; then
    name=$line
    case "$kind" in
      --include-struct | --include-union)
        [ -f "$output/$name.java" ] || missing+=("$kind $name")
        ;;
      --include-typedef)
        [ -f "$output/$name.java" ] || grep -rqw -- "$name" "$output" || missing+=("$kind $name")
        ;;
      *)
        # Functions, variables and constants each get a static accessor named after them
        grep -rqE -- "public static [^=(]*[ ]$name\(" "$output" || missing+=("$kind $name")
        ;;
    esac
    kind=""
  elif [[ "$line" == --include-* ]]; then
    kind=$line
  fi
done < "$arguments"

if [ ${#missing[@]} -eq 0 ]; then
  echo "Every symbol of $arguments was generated"
  exit 0
fi

echo "::error::jextract did not generate ${#missing[@]} symbol(s) of $arguments:"
printf '  %s\n' "${missing[@]}"
dump=$(mktemp)
if "$jextract" "@$arguments" --dump-includes "$dump" "$header" > /dev/null 2>&1; then
  echo "What the parser saw of them:"
  for entry in "${missing[@]}"; do
    grep -w -- "${entry#* }" "$dump" || echo "  ${entry#* }: not seen in $header"
  done
fi
exit 1
