SUBDIRS := $(wildcard client*)

.PHONY: all clean $(SUBDIRS)

all clean: $(SUBDIRS)

$(SUBDIRS):
	$(MAKE) $(MFLAGS) -C $@ $(MAKECMDGOALS)

