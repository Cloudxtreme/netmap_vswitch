#

SUBSYS := vale


DRIVERS = netmap/ e1000/ veth/ virtio_net/
MOD_LIST:= CONFIG_NETMAP=m CONFIG_E1000=m  CONFIG_VETH=m CONFIG_VIRTIO_NET=m

MOD_LIST += $(foreach s,$(SUBSYS), CONFIG_NETMAP_$(shell echo $s|tr a-z A-Z)=y)

M:=$(PWD)
# Additional compile flags (e.g. header location)

EXTRA_CFLAGS := -I$(root_dir)/drivers -I$(root_dir)/include -DCONFIG_NETMAP
EXTRA_CFLAGS += $(foreach s,$(SUBSYS),-DCONFIG_NETMAP_$(shell echo $s|tr a-z A-Z))

EXTRA_CFLAGS += -Wno-unused-but-set-variable

obj-m += $(O_DRIVERS)
all: build

build:
	$(MAKE) -C $(KSRC) M=$(PWD) $(MOD_LIST) modules \
			EXTRA_CFLAGS='$(EXTRA_CFLAGS)'	\
			O_DRIVERS="$(DRIVERS:%.c=%.o)"
	@ls -l `find . -name \*.ko`

clean:
	-@ $(MAKE) -C $(KSRC) M=$(PWD) clean 2> /dev/null
	-@ (rm -rf *.orig *.rej *.ko *.o .*.d \
			.tmp_versions *.mod.c modules.order \
			Module.symvers .*.cmd get-drivers )

define remote_template
$$(obj)/$(1): $$(M)/netmap/$(1:.o=.c)
	$$(call cmd,cc_o_c)
	$$(call cmd,modversions)
endef

$(foreach o,$(remoteobjs),$(eval $(call remote_template,$(o))))
