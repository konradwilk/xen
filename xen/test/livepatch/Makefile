include $(XEN_ROOT)/Config.mk

ifeq ($(XEN_TARGET_ARCH),x86_64)
OBJCOPY_MAGIC := -I binary -O elf64-x86-64 -B i386:x86-64
# The ELF reloc points to one byte past the instruction. If we need to replace
# the whole insn we need to subtract 1 (and make the insn of length 5).
RELOC_SUBTRACT := 1
else
  ifeq ($(XEN_TARGET_ARCH),arm32)
  OBJCOPY_MAGIC := -I binary -O elf32-littlearm -B arm
  else
  OBJCOPY_MAGIC := -I binary -O elf64-littleaarch64 -B aarch64
  endif
# ARM isn are always 4 bytes.
RELOC_SUBTRACT := 0
endif
TEXT_START=$(shell $(NM) --defined $(1) | grep T | sort | head -1 | awk ' { printf("%d",strtonum("0x"$$1))}')
RELOC_OFFSET=$(shell $(CROSS_COMPILE)readelf --relocs $(1) | awk '/rela.text/ { $$0=""; check=1 }\
                                            /Relocation/ { check=0 } \
                                           /$(2)/ { if (check) printf("%d",strtonum("0x"$$1) - $(RELOC_SUBTRACT) ) }')

CODE_ADDR=$(shell nm --defined $(1) | grep $(2) | awk '{print "0x"$$1}')
CODE_SZ=$(shell nm --defined -S $(1) | grep $(2) | awk '{ print "0x"$$2}')

.PHONY: default

LIVEPATCH := xen_hello_world.livepatch
LIVEPATCH_BYE := xen_bye_world.livepatch
LIVEPATCH_REPLACE := xen_replace_world.livepatch
LIVEPATCH_FOOBAR := xen_foobar.livepatch
LIVEPATCH_FOOBAR_NOP := xen_foobar_nop.livepatch

default: livepatch

install: livepatch
	$(INSTALL_DATA) $(LIVEPATCH) $(DESTDIR)$(DEBUG_DIR)/$(LIVEPATCH)
	$(INSTALL_DATA) $(LIVEPATCH_BYE) $(DESTDIR)$(DEBUG_DIR)/$(LIVEPATCH_BYE)
	$(INSTALL_DATA) $(LIVEPATCH_REPLACE) $(DESTDIR)$(DEBUG_DIR)/$(LIVEPATCH_REPLACE)
	$(INSTALL_DATA) $(LIVEPATCH_FOOBAR) $(DESTDIR)$(DEBUG_DIR)/$(LIVEPATCH_FOOBAR)
	$(INSTALL_DATA) $(LIVEPATCH_FOOBAR_NOP) $(DESTDIR)$(DEBUG_DIR)/$(LIVEPATCH_FOOBAR_NOP)


uninstall:
	rm -f $(DESTDIR)$(DEBUG_DIR)/$(LIVEPATCH)
	rm -f $(DESTDIR)$(DEBUG_DIR)/$(LIVEPATCH_BYE)
	rm -f $(DESTDIR)$(DEBUG_DIR)/$(LIVEPATCH_REPLACE)
	rm -f $(DESTDIR)$(DEBUG_DIR)/$(LIVEPATCH_FOOBAR)
	rm -f $(DESTDIR)$(DEBUG_DIR)/$(LIVEPATCH_FOOBAR_NOP)


.PHONY: clean
clean::
	rm -f *.o .*.o.d *.livepatch config.h

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

.PHONY: $(LIVEPATCH)
$(LIVEPATCH): xen_hello_world_func.o xen_hello_world.o note.o
	$(LD) $(LDFLAGS) $(build_id_linker) -r -o $(LIVEPATCH) $^

#
# This target is only accessible if CONFIG_LIVEPATCH is defined, which
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
	$(OBJCOPY) $(OBJCOPY_MAGIC) \
		   --rename-section=.data=.livepatch.depends -S $@.bin $@
	rm -f $@.bin

#
# Extract the build-id of the xen_hello_world.livepatch
# (which xen_bye_world will depend on).
#
.PHONY: hello_world_note.o
hello_world_note.o: $(LIVEPATCH)
	$(OBJCOPY) -O binary --only-section=.note.gnu.build-id $(LIVEPATCH) $@.bin
	$(OBJCOPY) $(OBJCOPY_MAGIC) \
		   --rename-section=.data=.livepatch.depends -S $@.bin $@
	rm -f $@.bin

xen_bye_world.o: config.h

.PHONY: $(LIVEPATCH_BYE)
$(LIVEPATCH_BYE): xen_bye_world_func.o xen_bye_world.o hello_world_note.o
	$(LD) $(LDFLAGS) $(build_id_linker) -r -o $(LIVEPATCH_BYE) $^

xen_replace_world.o: config.h

.PHONY: $(LIVEPATCH_REPLACE)
$(LIVEPATCH_REPLACE): xen_replace_world_func.o xen_replace_world.o note.o
	$(LD) $(LDFLAGS) $(build_id_linker) -r -o $(LIVEPATCH_REPLACE) $^

xen_foobar.o: config.h

.PHONY: $(LIVEPATCH_FOOBAR)
$(LIVEPATCH_FOOBAR): xen_foobar.o note.o
	$(LD) $(LDFLAGS) $(build_id_linker) -r -o $(LIVEPATCH_FOOBAR) $^

xen_foobar.o: config.h

.PHONY: $(LIVEPATCH_FOOBAR)
$(LIVEPATCH_FOOBAR): xen_foobar.o note.o
	$(LD) $(LDFLAGS) $(build_id_linker) -r -o $(LIVEPATCH_FOOBAR) $^

#
# We extract from --reloc output the offset in the relocation for the call for
# the 'bar' function
#
.PHONY: config-reloc.h
config-reloc.h: OLD_CODE_SZ=$(call CODE_SZ,$(LIVEPATCH_FOOBAR),xen_extra_version)
config-reloc.h: START_TEXT=$(call TEXT_START,$(LIVEPATCH_FOOBAR))
config-reloc.h: OFFSET=$(call RELOC_OFFSET,$(LIVEPATCH_FOOBAR),bar)
config-reloc.h: SUBTRACTION=$(shell expr $(OFFSET) - $(START_TEXT))
config-reloc.h: BAR_OFFSET=$(shell printf ""0x%x"" $(OFFSET))
config-reloc.h: $(LIVEPATCH_FOOBAR)
	(set -e; \
	 echo "#define OLD_CODE_SZ $(OLD_CODE_SZ)"; \
	 echo "#define START_TEXT $(START_TEXT)"; \
	 echo "#define OFFSET $(OFFSET)"; \
	 echo "#define TEST $(SUBTRACTION)"; \
	 echo "#define BAR_OFFSET \"$(BAR_OFFSET)\"") > $@

.PHONY: xen_foobar_note.o
xen_foobar_note.o: $(LIVEPATCH_FOOBAR)
	$(OBJCOPY) -O binary --only-section=.note.gnu.build-id $(LIVEPATCH_FOOBAR) $@.bin
	$(OBJCOPY)  $(OBJCOPY_MAGIC) \
		   --rename-section=.data=.livepatch.depends -S $@.bin $@
	rm -f $@.bin

xen_foobar_nop.o: config-reloc.h

.PHONY: $(LIVEPATCH_FOOBAR_NOP)
$(LIVEPATCH_FOOBAR_NOP): xen_foobar_nop.o xen_foobar_note.o
	$(LD) $(LDFLAGS) $(build_id_linker) -r -o $(LIVEPATCH_FOOBAR_NOP) $^


.PHONY: livepatch
livepatch: $(LIVEPATCH) $(LIVEPATCH_BYE) $(LIVEPATCH_REPLACE) \
	$(LIVEPATCH_FOOBAR) $(LIVEPATCH_FOOBAR_NOP)
