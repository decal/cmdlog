#
# Makefile for the CMDLOG LSM
#

obj-$(CONFIG_SECURITY_CMDLOG) := cmdlog.o

cmdlog-y := cmdlog_lsm.o 
