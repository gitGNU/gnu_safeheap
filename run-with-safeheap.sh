#!/bin/sh
G_SLICE=always-malloc LD_PRELOAD=/usr/lib/libsafeheap.so $@
exit $?

