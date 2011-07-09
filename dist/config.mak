#use extra warnings, may disturb older compilers
CFLAGS+=-Wextra 

#use stack protector, may disturb older compilers
CFLAGS+=-fstack-protector-all -D_FORTIFY_SOURCE=2 

#set size of static buffer
CFLAGS+=-DUSER_BUFSIZE_KB=96 

#set number of maximum connections (if more than FD_SETSIZE, it will be overridden in source)
CFLAGS+=-DUSER_MAX_FD=1024


