#include <stdio.h>
#include "../RSScript.h"
#include "../../../lib/stringptr.h"
//RcB: DEP "../RSScript.c"

int main(int argc, char** argv) {
	RSScript ss, *s = &ss;
	rss_init(s, argc, argv);
	
	rss_http_request* req = rss_get_request(s);
	(void) req;
	
	if(!rss_is_cookie_authed(s)) {
		rss_redirect_hard(s, SPLITERAL("/login.html"));
		rss_free(s);
		exit(0);
	}
	
	rss_set_cookie_authed(s, NULL);
	if(req->upload_fn) {
		rss_write_attachment(s, SPLITERAL("/tmp/testfile"));
		rss_redirect_soft(s, SPLITERAL("main.cgi"));
	} else
		rss_respond500(s);
	
	rss_free(s);
	return 0;
}
