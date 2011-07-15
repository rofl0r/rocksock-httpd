MYLIB=../../../lib
INCLUDES=${MYLIB}
LINKDIRS=${MYLIB}
ROCKSOCK=../../../rocksock

CFLAGS_OWN=-Wall -D_GNU_SOURCE -DKDEVELOP_BUG

SOURCEFILES=../RSScript.c
INCFILES=${ROCKSOCK}/rocksockserver.c ${MYLIB}/strlib.c ${MYLIB}/stringptr.c ${MYLIB}/fileparser.c ${MYLIB}/kvlist.c

-include ../../config.mak

CFLAGS_OPT=-s -Os
CFLAGS_DBG=-g -DDEBUG

all: debug

optimized:
	${CC} ${CFLAGS_OWN} ${CFLAGS_OPT} -I ${INCLUDES} ${SOURCEFILES} main.c ${INCFILES} ${LINKLIBS} ${CFLAGS} -o main.cgi
	${CC} ${CFLAGS_OWN} ${CFLAGS_OPT} -I ${INCLUDES} ${SOURCEFILES} login.c ${INCFILES} ${LINKLIBS} ${CFLAGS} -o login.cgi
	${CC} ${CFLAGS_OWN} ${CFLAGS_OPT} -I ${INCLUDES} ${SOURCEFILES} upload.c ${INCFILES} ${LINKLIBS} ${CFLAGS} -o upload.cgi
	${CC} ${CFLAGS_OWN} ${CFLAGS_OPT} -I ${INCLUDES} ${SOURCEFILES} form.c ${INCFILES} ${LINKLIBS} ${CFLAGS} -o form.cgi

debug:
	${CC} ${CFLAGS_OWN} ${CFLAGS_DBG} -I ${INCLUDES} ${SOURCEFILES} main.c ${INCFILES} ${LINKLIBS} ${CFLAGS} -o main.cgi
	${CC} ${CFLAGS_OWN} ${CFLAGS_DBG} -I ${INCLUDES} ${SOURCEFILES} login.c ${INCFILES} ${LINKLIBS} ${CFLAGS} -o login.cgi
	${CC} ${CFLAGS_OWN} ${CFLAGS_DBG} -I ${INCLUDES} ${SOURCEFILES} upload.c ${INCFILES} ${LINKLIBS} ${CFLAGS} -o upload.cgi
	${CC} ${CFLAGS_OWN} ${CFLAGS_DBG} -I ${INCLUDES} ${SOURCEFILES} form.c ${INCFILES} ${LINKLIBS} ${CFLAGS} -o form.cgi

.PHONY: all optimized debug
