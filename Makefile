INCLUDES="."
LINKDIRS=
LINKLIBS=

MAINFILE=httpserver.c

CFLAGS_OWN=-Wall -D_GNU_SOURCE
CFLAGS_DBG=-g
CFLAGS_OPT=-s -Os

-include config.mak

CFLAGS_RCB_OPT=${CFLAGS_OWN} ${CFLAGS_OPT} -I ${INCLUDES} ${LINKLIBS} ${CFLAGS}
CFLAGS_RCB_DBG=${CFLAGS_OWN} ${CFLAGS_DBG} -I ${INCLUDES} ${LINKLIBS} ${CFLAGS}

all: debug

optimized:
	CFLAGS="${CFLAGS_RCB_OPT}" rcb --force $(RCBFLAGS) ${MAINFILE} $(LINKLIBS)
	strip --remove-section .comment httpserver.out

debug:
	CFLAGS="${CFLAGS_RCB_DBG}" rcb --force $(RCBFLAGS) ${MAINFILE} $(LINKLIBS)


.PHONY: all optimized debug
