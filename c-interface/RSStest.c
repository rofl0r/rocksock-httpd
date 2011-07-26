#include <stdio.h>
#include "RSScript.h"

#define fo_sure
int main(int argc, char** argv) {
	RSScript ss, *s = &ss;
#ifdef fo_sure
	rss_init(s, argc, argv);
#else
	// TODO
#endif
	puts(rss_get_ip(s)->ptr);
	rss_respond404(s);
	
	rss_free(s);
	return 0;
}

