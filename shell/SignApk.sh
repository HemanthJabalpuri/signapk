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

# copy whole file except last 2 bytes
fsize=$(stat -c "%s" "$f")
dd if="$f" of="$o" status=none iflag=count_bytes bs=4096 count=$((fsize-2))

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
