include $(XEN_ROOT)/Config.mk

CODE_ADDR=$(shell nm --defined $(1) | grep $(2) | awk '{print "0x"$$1}')
CODE_SZ=$(shell nm --defined -S $(1) | grep $(2) | awk '{ print "0x"$$2}')

.PHONY: default

XLIVE_PATCH := xen_hello_world.xlive_patch
XLIVE_PATCH_BYE := xen_bye_world.xlive_patch
XLIVE_PATCH_REPLACE := xen_replace_world.xlive_patch

default: xlive_patch

install: xlive_patch
	$(INSTALL_DATA) $(XLIVE_PATCH) $(DESTDIR)$(DEBUG_DIR)/$(XLIVE_PATCH)
	$(INSTALL_DATA) $(XLIVE_PATCH_BYE) $(DESTDIR)$(DEBUG_DIR)/$(XLIVE_PATCH_BYE)
	$(INSTALL_DATA) $(XLIVE_PATCH_REPLACE) $(DESTDIR)$(DEBUG_DIR)/$(XLIVE_PATCH_REPLACE)
uninstall:
	rm -f $(DESTDIR)$(DEBUG_DIR)/$(XLIVE_PATCH)
	rm -f $(DESTDIR)$(DEBUG_DIR)/$(XLIVE_PATCH_BYE)
	rm -f $(DESTDIR)$(DEBUG_DIR)/$(XLIVE_PATCH_REPLACE)

.PHONY: clean
clean::
	rm -f *.o .*.o.d *.xlive_patch config.h

#
# To compute these values we need the binary files: xen-syms
# and xen_hello_world_func.o to be already compiled.
#
.PHONY: config.h
config.h: OLD_CODE_SZ=$(call CODE_SZ,$(BASEDIR)/xen-syms,xen_extra_version)
config.h: NEW_CODE_SZ=$(call CODE_SZ,$<,xen_hello_world)
config.h: xen_hello_world_func.o
	(set -e; \
	 echo "#define NEW_CODE_SZ $(NEW_CODE_SZ)"; \
	 echo "#define OLD_CODE_SZ $(OLD_CODE_SZ)") > $@

xen_hello_world.o: config.h

.PHONY: $(XLIVE_PATCH)
$(XLIVE_PATCH): xen_hello_world_func.o xen_hello_world.o note.o
	$(LD) $(LDFLAGS) $(build_id_linker) -r -o $(XLIVE_PATCH) $^

#
# This target is only accessible if CONFIG_XLIVE_PATCH is defined, which
# depends on $(build_id_linker) being available. Hence we do not
# need any checks.
#
# N.B. The reason we don't use arch/x86/note.o is that it may
# not be built (it is for EFI builds), and that we do not have
# the note.o.bin to muck with (as it gets deleted)
#
.PHONY: note.o
note.o:
	$(OBJCOPY) -O binary --only-section=.note.gnu.build-id $(BASEDIR)/xen-syms $@.bin
	$(OBJCOPY) -I binary -O elf64-x86-64 -B i386:x86-64 \
		   --rename-section=.data=.xlive_patch.depends -S $@.bin $@
	rm -f $@.bin

#
# Extract the build-id of the xen_hello_world.xlive_patch
# (which xen_bye_world will depend on).
#
.PHONY: hello_world_note.o
hello_world_note.o: $(XLIVE_PATCH)
	$(OBJCOPY) -O binary --only-section=.note.gnu.build-id $(XLIVE_PATCH) $@.bin
	$(OBJCOPY)  -I binary -O elf64-x86-64 -B i386:x86-64 \
		   --rename-section=.data=.xlive_patch.depends -S $@.bin $@
	rm -f $@.bin

xen_bye_world.o: config.h

.PHONY: $(XLIVE_PATCH_BYE)
$(XLIVE_PATCH_BYE): xen_bye_world_func.o xen_bye_world.o hello_world_note.o
	$(LD) $(LDFLAGS) $(build_id_linker) -r -o $(XLIVE_PATCH_BYE) $^

xen_replace_world.o: config.h

.PHONY: $(XLIVE_PATCH_REPLACE)
$(XLIVE_PATCH_REPLACE): xen_replace_world_func.o xen_replace_world.o note.o
	$(LD) $(LDFLAGS) $(build_id_linker) -r -o $(XLIVE_PATCH_REPLACE) $^

.PHONY: xlive_patch
xlive_patch: $(XLIVE_PATCH) $(XLIVE_PATCH_BYE) $(XLIVE_PATCH_REPLACE)
