AM_CPPFLAGS = @RX_INCLUDES@
LIBS = @LIBS@ @RX_LIBS@

noinst_PROGRAMS = x3
EXTRA_PROGRAMS = checkdb globtest
noinst_DATA = chanserv.help global.help modcmd.help nickserv.help opserv.help saxdb.help sendmail.help mod-sockcheck.help mod-helpserv.help mod-memoserv.help
EXTRA_DIST = $(noinst_DATA)

EXTRA_x3_SOURCES = alloc-slab.c alloc-x3.c proto-bahamut.c proto-common.c proto-p10.c mod-snoop.c mod-memoserv.c mod-helpserv.c mod-sockcheck.c
x3_LDADD = @MODULE_OBJS@
x3_DEPENDENCIES = @MODULE_OBJS@
x3_SOURCES = \
	chanserv.c chanserv.h \
	compat.c compat.h \
	conf.c conf.h \
	dict-splay.c dict.h \
	getopt.c getopt.h \
	getopt1.c getopt.h \
	gline.c gline.h \
	global.c global.h \
	hash.c hash.h \
	heap.c heap.h \
	helpfile.c helpfile.h \
	ioset.c ioset.h \
	log.c log.h \
	main.c common.h \
	math.c \
	md5.c md5.h \
	modcmd.c modcmd.h \
	modules.c modules.h \
	nickserv.c nickserv.h \
	opserv.c opserv.h \
	policer.c policer.h \
	proto.h \
	recdb.c recdb.h \
	saxdb.c saxdb.h \
	sendmail.c sendmail.h \
	timeq.c timeq.h \
	tools.c

checkdb_SOURCES = checkdb.c common.h compat.c compat.h dict-splay.c dict.h recdb.c recdb.h saxdb.c saxdb.h tools.c conf.h log.h modcmd.h saxdb.h timeq.h
globtest_SOURCES = common.h compat.c compat.h dict-splay.c dict.h globtest.c tools.c
