INCLUDES="../lib"
LINKDIRS="../lib"
MYLIB="../lib"
ROCKSOCK="../rocksock"
#LINKLIBS="-lpthread"

OUTFILE=httpserver
CFLAGS="-D_GNU_SOURCE -fstack-protector-all -D_FORTIFY_SOURCE=2"

INCFILES=${ROCKSOCK}/rocksockserver.c ${MYLIB}/strlib.c ${MYLIB}/stringptr.c ${MYLIB}/optparser.c

all: debug

optimized:
	${CC} ${CFLAGS} -fno-strict-aliasing -Wall -Wextra -O3 -I ${INCLUDES} httpserver.c  ${INCFILES} ${LINKLIBS} -o ${OUTFILE}-$@
	strip ${OUTFILE}-$@

debug:
	${CC} ${CFLAGS} -Wall -Wextra -g -I ${INCLUDES} httpserver.c ${INCFILES} ${LINKLIBS} -o ${OUTFILE}-$@


.PHONY: all optimized debug
