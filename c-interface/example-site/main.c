#include <stdio.h>
#include "../RSScript.h"
#include "../../../lib/stringptr.h"
//RcB: DEP "../RSScript.c"

int main(int argc, char** argv) {
	stringptr* html = SPLITERAL("<HTML>\n<BODY>\n<A HREF=\"/upload.html\">upload a file</A>\n<A HREF=\"/form.html\">test form</A>\n</BODY>\n</HTML>");

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
	rss_set_responsetype(s, 200);
	rss_set_contenttype(s, SPLITERAL("text/html"));
	rss_respond(s, html);
	rss_submit(s);
	
	rss_free(s);
	return 0;
}
