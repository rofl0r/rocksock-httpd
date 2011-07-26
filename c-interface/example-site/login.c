#include <stdio.h>
#include "../RSScript.h"
#include "../../../lib/include/stringptr.h"

int main(int argc, char** argv) {
	
	stringptr* username = SPLITERAL("admin");
	stringptr* password = SPLITERAL("pa55word"); // omg leet
	
	stringptr *u, *p;
	
	RSScript ss, *s = &ss;
	rss_init(s, argc, argv);
	
	rss_http_request* req = rss_get_request(s);
	(void) req;
	
	if(kv_find(req->formdata, SPLITERAL("user"), (void**) &u) && kv_find(req->formdata, SPLITERAL("pass"), (void**) &p) && 
		stringptr_eq(u, username) && stringptr_eq(p, password)
	) {
		rss_make_auth_cookie(s);
		rss_redirect_soft(s, SPLITERAL("/main.cgi"));
	} else 
		rss_redirect_soft(s, SPLITERAL("/login.html"));
	
	rss_free(s);
	return 0;
}
