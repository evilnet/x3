AM_CPPFLAGS = @RX_INCLUDES@ -DSYSCONFDIR=\"@sysconfdir@\" -DPKGDATADIR=\"@datadir@/x3\" -DLOCALSTATEDIR=\"@localstatedir@/x3\"
LIBS = @LIBS@ @RX_LIBS@
TRACK = @TRACK@
pythonpath = @pythonpath@
PY_CFLAGS = @PY_CFLAGS@
PY_LIBS = @PY_LIBS@


bin_PROGRAMS = x3
noinst_PROGRAMS = slab-read
EXTRA_PROGRAMS = checkdb globtest
noinst_DATA = \
	chanserv.help \
	global.help \
	modcmd.help \
	nickserv.help \
	opserv.help \
	saxdb.help \
	mail.help \
	spamserv.help \
	mod-sockcheck.help \
	mod-helpserv.help \
	mod-memoserv.help \
        mod-qserver.help \
        mod-snoop.help \
	mod-webtv.help \
	mod-python.help

EXTRA_DIST = $(noinst_DATA)

EXTRA_x3_SOURCES = \
	alloc-slab.c \
	alloc-x3.c \
	ioset-epoll.c \
	ioset-kevent.c \
	ioset-select.c \
	mail-common.c \
	mail-sendmail.c \
	main-common.c \
	proto-common.c \
	proto-p10.c \
	mod-blacklist.c \
	mod-snoop.c \
	mod-track.c \
	mod-memoserv.c \
	mod-helpserv.c \
	mod-sockcheck.c \
	mod-webtv.c \
	mod-python.c \
	mod-qserver.c

x3_LDADD = @MODULE_OBJS@
x3_DEPENDENCIES = @MODULE_OBJS@
x3_SOURCES = \
	base64.c base64.h \
	chanserv.c chanserv.h \
	compat.c compat.h \
	conf.c conf.h \
	dict-splay.c dict.h \
    eventhooks.c eventhooks.h \
	getopt.c getopt.h \
	getopt1.c getopt.h \
	gline.c gline.h \
	global.c global.h \
	hash.c hash.h \
	heap.c heap.h \
	helpfile.c helpfile.h \
	ioset.c ioset.h ioset-impl.h \
	log.c log.h \
	mail.h \
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
	sar.c sar.h \
	saxdb.c saxdb.h \
	spamserv.c spamserv.h \
	shun.c shun.h \
	timeq.c timeq.h \
	tools.c x3ldap.c x3ldap.h \
	version.c version.h

checkdb_SOURCES = checkdb.c common.h compat.c compat.h dict-splay.c dict.h recdb.c recdb.h saxdb.c saxdb.h tools.c conf.h log.h modcmd.h saxdb.h timeq.h
globtest_SOURCES = common.h compat.c compat.h dict-splay.c dict.h globtest.c tools.c
slab_read_SOURCES = slab-read.c

version.c: version.c.SH
	${SHELL} ${srcdir}/version.c.SH

.PHONY: version.c
