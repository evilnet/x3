#! /bin/sh

aclocal -Wall
autoheader -Wall
automake --gnu -a -c
autoconf -Wall
