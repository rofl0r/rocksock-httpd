#use extra warnings, may disturb older compilers
CFLAGS+=-Wextra 

#use stack protector, may disturb older compilers
CFLAGS+=-fstack-protector-all -D_FORTIFY_SOURCE=2 

#set size of static buffer
CFLAGS+=-DUSER_BUFSIZE_KB=96 

#set number of maximum connections (if more than FD_SETSIZE, it will be overridden in source)
CFLAGS+=-DUSER_MAX_FD=1024

#put every function in a separate section and attempt dead-code-elimination
CFLAGS+=-ftree-dce -fdata-sections -ffunction-sections -Wl,--gc-sections

#link time optimization. gets another 4 KB of bloat removed here
CFLAGS+=-flto -fwhole-program

#allow directory traversal
#CFLAGS+=-DALLOW_TRAVERSAL

