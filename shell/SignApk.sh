#!/bin/sh

# Sign zip files with testkey for flashing in Android recovery
# this is a Shell port of Java source
# depends on `openssl`
# can run in dash, bash and busybox environments
#
# put testkey.pk8 and testkey.sbt in the same folder as script
#
# Author : HemanthJabalpuri
# Date   : 16th October 2023

abort() {
  echo "$1"
  exit 1
}

if [ $# -lt 2 ]; then
  abort "Usage: sh SignApk.sh in.zip out.zip"
fi

tmpd="$PWD"; [ "$PWD" = "/" ] && tmpd=""
case "$0" in
  /*) cdir="$0";;
  *) cdir="$tmpd/${0#./}";;
esac
cdir="${cdir%/*}"

f="$1"
o="$2"
PKEY="$cdir/testkey.pk8"
SBT="$cdir/testkey.sbt"

getData() {
  dd if="$f" status=none iflag=skip_bytes,count_bytes bs=4096 skip=$1 count=$2
}

getByte() {
  getData $1 1 | od -A n -t x1 | tr -d " "
}

fsize=$(stat -c "%s" "$f")

# check if already comment is there
tail1=$(getByte $((fsize-22)))
tail2=$(getByte $((fsize-21)))
tail3=$(getByte $((fsize-20)))
if [ $tail1 != "50" -o $tail2 != "4b" -o $tail3 != "05" ]; then
  abort "zip data already has an archive comment"
fi

# copy whole file except last 2 bytes
getData 0 $((fsize-2)) > "$o"

sign="$(openssl dgst -sha1 -hex -sign "$PKEY" "$o")"
sign="$(echo "$sign" | cut -d "=" -f 2 | tr -d " " | sed -e 's/../\\x&/g')"

{
  env printf '\xca\x06'
  printf 'signed by SignApk'
  env printf '\x00'
  cat "$SBT"
  env printf "$sign"
  env printf '\xb8\x06\xff\xff\xca\x06'
} >> "$o"
