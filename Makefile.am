EXTRA_DIST = FAQ x3.conf.example sockcheck.conf.example autogen.sh
SUBDIRS = @MY_SUBDIRS@
PY_CFLAGS = @PY_CFLAGS@
PY_LIBS = @PY_LIBS@
pythonpath = @pythonpath@

DIST_SUBDIRS = src rx

all: x3

x3: src/x3
	cp ./src/x3 $(srcdir)/src/*.help .

install-exec-local:
	$(INSTALL) -d -m 755 $(bindir)
	$(INSTALL) -d -m 755 $(sysconfdir)
	$(INSTALL) -d -m 755 $(datadir)/x3
	$(INSTALL) -m 644 $(srcdir)/src/*.help $(datadir)/x3
	$(INSTALL) -m 600 $(srcdir)/x3.conf.example $(datadir)/x3
	$(INSTALL) -m 644 $(srcdir)/sockcheck.conf.example $(datadir)/x3
	$(INSTALL) -m 644 $(srcdir)/src/modpython.py $(datadir)/x3
	./install-r.sh $(srcdir)/src/plugins $(datadir)/x3/plugins
	@echo
	@echo X3-$(VERSION) has been installed to $(prefix)
	@echo Binaries: $(bindir)
	@echo Config: $(sysconfdir)
	@echo Templates: $(datadir)/x3
	@echo Remember to edit $(sysconfdir)/x3.conf.example
	@echo
