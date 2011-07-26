INCLUDES="."
LINKDIRS=
LINKLIBS=

CFLAGS_OWN=-Wall -D_GNU_SOURCE -DCOOKIE_DB=\\\"/tmp/cookie.db\\\"
CFLAGS_DBG=-g
CFLAGS_OPT=-s -Os

-include config.mak

CFLAGS_RCB_OPT=${CFLAGS_OWN} ${CFLAGS_OPT} -I ${INCLUDES} ${LINKLIBS} ${CFLAGS}
CFLAGS_RCB_DBG=${CFLAGS_OWN} ${CFLAGS_DBG} -I ${INCLUDES} ${LINKLIBS} ${CFLAGS}

all: debug

optimized:
	CFLAGS="${CFLAGS_RCB_OPT}" rcb --force main.c
	CFLAGS="${CFLAGS_RCB_OPT}" rcb --force login.c
	CFLAGS="${CFLAGS_RCB_OPT}" rcb --force upload.c
	CFLAGS="${CFLAGS_RCB_OPT}" rcb --force form.c

debug:
	CFLAGS="${CFLAGS_RCB_DBG}" rcb --force main.c
	CFLAGS="${CFLAGS_RCB_DBG}" rcb --force login.c
	CFLAGS="${CFLAGS_RCB_DBG}" rcb --force upload.c
	CFLAGS="${CFLAGS_RCB_DBG}" rcb --force form.c


.PHONY: all optimized debug
