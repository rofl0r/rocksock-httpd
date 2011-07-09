#use extra warnings
CFLAGS+=-Wextra 
#use stack protector
CFLAGS+=-fstack-protector-all -D_FORTIFY_SOURCE=2
