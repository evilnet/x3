#! /bin/sh

~/compiled/bin/aclocal
~/compiled/bin/autoheader -Wall
~/compiled/bin/automake -a --gnu Makefile rx/Makefile src/Makefile
~/compiled/bin/autoconf -Wall
