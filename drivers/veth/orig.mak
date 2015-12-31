#
# Makefile for the veth netmap driver
#

obj-$(CONFIG_VETH) += veth_netmap.o

veth_netmap-objs := veth.o
