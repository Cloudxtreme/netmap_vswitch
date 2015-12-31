#
# Makefile for the virtio netmap driver
#

obj-$(CONFIG_VIRTIO_NET) += virtio_netmap.o

virtio_netmap-objs := virtio_net.o

