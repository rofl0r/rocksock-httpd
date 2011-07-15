INCLUDES=../lib
LINKDIRS=../lib
MYLIB=../../lib
ROCKSOCK=../../rocksock
#LINKLIBS="-lpthread"

OUTFILE=testscript
CFLAGS_OWN=-Wall -D_GNU_SOURCE

SOURCEFILES=./RSScript.c ./RSStest.c
INCFILES=${ROCKSOCK}/rocksockserver.c ${MYLIB}/strlib.c ${MYLIB}/stringptr.c ${MYLIB}/fileparser.c ${MYLIB}/kvlist.c

-include ../config.mak

all: debug

optimized:
	${CC} ${CFLAGS_OWN} -s -Os -I ${INCLUDES} ${SOURCEFILES} ${INCFILES} ${LINKLIBS} ${CFLAGS} -o ${OUTFILE}-$@

debug:
	${CC} ${CFLAGS_OWN} -g -I ${INCLUDES} ${SOURCEFILES} ${INCFILES} ${LINKLIBS} ${CFLAGS} -o ${OUTFILE}-$@


.PHONY: all optimized debug
