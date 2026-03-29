#! /bin/sh

# This is a hacky solution to the problem of INSTALL not knowing how to recursively copy files
# and our need to recursively copy with exceptions the plugin tree. It works on linux,
# but needs serious work to be more portable. Please Help. -Rubin
SRC=$1
DST=$2

# TODO: find banaries like 'find' and 'cp' in common locations and/or path, and
# use them there instead of assuming they are in path.

if [ "_$DST" = _ ]; then
    exit
fi

cd `dirname "$SRC"`
SRCDIR=`basename "$SRC"`
find "$SRCDIR" \! -path '*/.*' | \
    while read f; do \
        d="$DST/${f#$SRCDIR/}"; \
        mkdir -p "$(dirname "$d")"; \
        if [ -f $f ]; then cp -v $f $d; fi; \
    done
# this will break if SRCDIR has hidden directories in it :/
#find "$SRCDIR" \! -path '*/.*'

