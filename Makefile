INCLUDES=../lib
LINKDIRS=../lib
MYLIB=../lib
ROCKSOCK=../rocksock
#LINKLIBS="-lpthread"

OUTFILE=httpserver
CFLAGS_OWN=-Wall -D_GNU_SOURCE 

INCFILES=${ROCKSOCK}/rocksockserver.c ${MYLIB}/strlib.c ${MYLIB}/stringptr.c ${MYLIB}/optparser.c

-include config.mak

all: debug

optimized:
	${CC} ${CFLAGS_OWN} -s -Os -I ${INCLUDES} httpserver.c  ${INCFILES} ${LINKLIBS} ${CFLAGS} -o ${OUTFILE}-$@

debug:
	${CC} ${CFLAGS_OWN} -g -I ${INCLUDES} httpserver.c ${INCFILES} ${LINKLIBS} ${CFLAGS} -o ${OUTFILE}-$@


.PHONY: all optimized debug
