#!/bin/sh
#
# run this script and pipe the output to LANG/strings.db, then change the english strings
# to LANG.  (where LANG is the language code, eg fr, de, etc). DO NOT change the order of %s %d etc
# in the help file!
# 
# Then, copy *.help into LANG/ and translate them too.
#
# thanks to Nei for this:
grep -lR ry\ ms ..|grep -v '{arch'|xargs perl -ne 'if(/message_entry msgtab/../{ NULL, NULL }/){print"$1 $2;\n"if/\s+{ (".*?"), (".*") },/}'
