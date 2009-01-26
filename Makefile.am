EXTRA_DIST = FAQ x3.conf.example sockcheck.conf.example
SUBDIRS = @MY_SUBDIRS@
PY_CFLAGS = @PY_CFLAGS@
PY_LIBS = @PY_LIBS@
pythonpath = @pythonpath@

DIST_SUBDIRS = src rx

all: x3

x3: src/x3
	cp ./src/x3 $(srcdir)/src/*.help .

install-exec-local:
	$(INSTALL) -d -m 755 $(prefix)
	$(INSTALL) -m 744 ./src/x3 $(prefix)
	$(INSTALL) -m 644 $(srcdir)/src/*.help $(prefix)
	$(INSTALL) -m 600 $(srcdir)/x3.conf.example $(prefix)
	$(INSTALL) -m 644 $(srcdir)/sockcheck.conf.example $(prefix)
	$(INSTALL) -m 644 $(srcdir)/src/modpython.py $(prefix)
	./install-r.sh $(srcdir)/src/plugins $(prefix)
	@echo
	@echo X3-$(VERSION) has been installed to $(prefix)
	@echo Remember to edit x3.conf.example and sockcheck.conf.example
	@echo And of course, ./x3 --help before starting.
	@echo
