#!/bin/sh
#
# check-kc.sh - guards for the vendored Keycloak client in src/kc/
#
#   tools/check-kc.sh                  boundary check (run by every make in src/)
#   tools/check-kc.sh <ircd-checkout>  boundary check, then drift check
#
# src/kc/ is a byte-for-byte copy of the Nefarious IRCd's kc client
# (ircd/kc/*.c and include/kc/*.h; src/kc/SOURCE names the commit and the
# files).  It talks to X3 only through the kc_event_ops / kc_log_ops
# adapters, so it may not include an X3 header.
#
# Boundary check: the same ALLOW-LIST the ircd's check-kc-boundary target
# (ircd/Makefile.in) enforces on its own copy.  kc code may include, in angle
# form only:
#
#   <kc/...>                       its own headers
#   <curl/...>  <openssl/...>      its two library dependencies
#   <jansson.h>                    ditto
#   <sys/...> <arpa/...> <netinet/...> <net/...>
#                                  POSIX namespaced headers
#   the C standard + top-level POSIX headers in KC_ALLOWED_STD_HDRS below
#
# Everything else -- every quoted include, and every angle include naming an
# X3 header (<nickserv.h>, <conf.h>, ...) -- fails.  A header name holding
# ".." fails too.  The list is changed in the ircd first, then here.
#
# Drift check: every file in src/kc/ but SOURCE must exist in the ircd
# checkout (a .c under ircd/kc/, a .h under include/kc/) and be identical to
# it.  A file in src/kc/ the ircd does not have fails; a file the ircd has
# and X3 does not copy (kc_webhook*.c, kc_http_sync.c, ...) is not an error.

KC_ALLOWED_STD_HDRS="
	assert.h complex.h ctype.h errno.h fenv.h float.h inttypes.h
	iso646.h limits.h locale.h math.h setjmp.h signal.h stdalign.h
	stdarg.h stdatomic.h stdbool.h stddef.h stdint.h stdio.h stdlib.h
	stdnoreturn.h string.h tgmath.h threads.h time.h uchar.h wchar.h
	wctype.h
	dirent.h dlfcn.h fcntl.h grp.h netdb.h poll.h pthread.h pwd.h
	regex.h sched.h semaphore.h strings.h syslog.h termios.h unistd.h"

top=`cd "\`dirname "$0"\`/.." && pwd` || exit 2
kcdir="$top/src/kc"

if [ ! -d "$kcdir" ]; then
	echo "check-kc: $kcdir does not exist" >&2
	exit 1
fi

# The files under src/kc/, one level of subdirectory included so a future
# src/kc/<sub>/ is covered too.
kc_files() {
	for f in "$kcdir"/* "$kcdir"/*/*; do
		[ -f "$f" ] || continue
		echo "$f"
	done
}

files=`kc_files`
if [ -z "$files" ]; then
	echo "check-kc: $kcdir is empty" >&2
	exit 1
fi

# --- boundary check -------------------------------------------------------
bad=''
for f in $files; do
	case "$f" in
	*.c|*.h) ;;
	*) continue ;;
	esac
	incs=`sed -n \
	    -e 's|^[[:space:]]*#[[:space:]]*include[[:space:]]*<\([^>]*\)>.*|A:\1|p' \
	    -e 's|^[[:space:]]*#[[:space:]]*include[[:space:]]*"\([^"]*\)".*|Q:\1|p' \
	    "$f"`
	for i in $incs; do
		h=${i#??}
		ok=no
		case "$i" in
		A:kc/*|A:curl/*|A:openssl/*|A:sys/*|A:arpa/*|A:netinet/*|A:net/*)
			ok=yes ;;
		A:jansson.h)
			ok=yes ;;
		A:*)
			for s in $KC_ALLOWED_STD_HDRS; do
				if [ "$h" = "$s" ]; then ok=yes; break; fi
			done ;;
		esac
		case "$h" in
		*..*) ok=no ;;
		esac
		if [ "$ok" = no ]; then bad="$bad ${f#$top/}:$h"; fi
	done
done
if [ -n "$bad" ]; then
	echo "ERROR: src/kc may not include these headers:"
	for b in $bad; do echo "  $b"; done
	echo "kc/ talks to X3 only via kc_event_ops/kc_log_ops."
	echo "The permitted set is documented at the top of tools/check-kc.sh."
	exit 1
fi

[ $# -eq 0 ] && exit 0

# --- drift check ----------------------------------------------------------
ircd=$1
if [ ! -d "$ircd/ircd/kc" ] || [ ! -d "$ircd/include/kc" ]; then
	echo "check-kc: $ircd is not an ircd checkout (no ircd/kc/ or include/kc/)" >&2
	exit 2
fi

drift=''
for f in $files; do
	rel=${f#$kcdir/}
	case "$rel" in
	SOURCE) continue ;;
	*.c) theirs="$ircd/ircd/kc/$rel" ;;
	*.h) theirs="$ircd/include/kc/$rel" ;;
	*) drift="$drift src/kc/$rel(not-a-kc-file)"; continue ;;
	esac
	if [ ! -f "$theirs" ]; then
		drift="$drift src/kc/$rel(not-in-ircd)"
	elif ! cmp -s "$f" "$theirs"; then
		drift="$drift src/kc/$rel(differs)"
	fi
done
if [ -n "$drift" ]; then
	echo "ERROR: src/kc does not match $ircd:"
	for d in $drift; do echo "  $d"; done
	echo "src/kc is a verbatim copy; change the ircd first, then copy again"
	echo "and update src/kc/SOURCE."
	exit 1
fi
exit 0
