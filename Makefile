INCLUDES=../lib
LINKDIRS=../lib
MYLIB=../lib
ROCKSOCK=../rocksock
#LINKLIBS="-lpthread"

OUTFILE=httpserver
CFLAGS_OWN=-Wall -D_GNU_SOURCE 
CFLAGS_OWN+=-Wextra -fstack-protector-all -D_FORTIFY_SOURCE=2

INCFILES=${ROCKSOCK}/rocksockserver.c ${MYLIB}/strlib.c ${MYLIB}/stringptr.c ${MYLIB}/optparser.c

all: debug

optimized:
	${CC} ${CFLAGS_OWN} -s -I ${INCLUDES} httpserver.c  ${INCFILES} ${LINKLIBS} ${CFLAGS} -o ${OUTFILE}-$@

debug:
	${CC} ${CFLAGS_OWN} -g -I ${INCLUDES} httpserver.c ${INCFILES} ${LINKLIBS} ${CFLAGS} -o ${OUTFILE}-$@


.PHONY: all optimized debug
