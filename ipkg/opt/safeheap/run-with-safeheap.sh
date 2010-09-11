#!/bin/sh
G_SLICE=always-malloc LD_PRELOAD=./libsafeheap.so /usr/bin/app-application $@
exit $?

