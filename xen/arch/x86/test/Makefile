include $(XEN_ROOT)/Config.mk

CODE_ADDR=$(shell nm --defined $(1) | grep $(2) | awk '{print "0x"$$1}')
CODE_SZ=$(shell nm --defined -S $(1) | grep $(2) | awk '{ print "0x"$$2}')

.PHONY: default

XSPLICE := xen_hello_world.xsplice

default: xsplice

install: xsplice
	$(INSTALL_DATA) $(XSPLICE) $(DESTDIR)$(DEBUG_DIR)/$(XSPLICE)
uninstall:
	rm -f $(DESTDIR)$(DEBUG_DIR)/$(XSPLICE)

.PHONY: clean
clean::
	rm -f *.o .*.o.d $(XSPLICE) config.h

#
# To compute these values we need the binary files: xen-syms
# and xen_hello_world_func.o to be already compiled.
#
# We can be assured that xen-syms is already built as we are
# the last entry in the build target.
#
.PHONY: config.h
config.h: OLD_CODE_SZ=$(call CODE_SZ,$(BASEDIR)/xen-syms,xen_extra_version)
config.h: NEW_CODE_SZ=$(call CODE_SZ,$<,xen_hello_world)
config.h: xen_hello_world_func.o
	(set -e; \
	 echo "#define NEW_CODE_SZ $(NEW_CODE_SZ)"; \
	 echo "#define OLD_CODE_SZ $(OLD_CODE_SZ)") > $@

.PHONY: xsplice
xsplice: config.h
	# Need to have these done in sequential order
	$(MAKE) -f $(BASEDIR)/Rules.mk xen_hello_world_func.o
	$(MAKE) -f $(BASEDIR)/Rules.mk xen_hello_world.o
	$(LD) $(LDFLAGS) -r -o $(XSPLICE) xen_hello_world_func.o \
		xen_hello_world.o
