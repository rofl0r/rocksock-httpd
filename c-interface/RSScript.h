#ifndef RSSCRIPT_H
#define RSSCRIPT_H

#include <stddef.h>

#include "../../lib/include/kvlist.h"
#include "../../lib/include/stringptr.h"
#include "../../lib/include/stringptrlist.h"

typedef enum {
	RM_GET,
	RM_POST
} rss_http_request_method;

typedef struct {
	stringptr* uri;
	kvlist* reqdata;
	kvlist* getparams;
	kvlist* formdata;
	kvlist* cookies;
	
	stringptr* upload_fn;
	stringptr* boundary;
	
	size_t headersize;
	size_t multishitheadersize;
	rss_http_request_method meth;
} rss_http_request;

typedef struct {
	char* request_fn;
	char* response_fn;
	char* info_fn;
	size_t response_len;
	size_t response_linecount;
	rss_http_request req;
	kvlist* info;
	kvlist* response_cookies[16];
	size_t response_cookie_count;
	int response_err;
	stringptr* response_contenttype;
	stringptrlist* response_lines;
} RSScript;

void rss_init(RSScript* script, int argc, char** argv);
void rss_free(RSScript* script);
stringptr* url_encode(stringptr* url);
stringptr* url_decode(stringptr* url);
void rss_read_request(RSScript* script);
void rss_write_attachment(RSScript* script, stringptr* outname);
rss_http_request* rss_get_request(RSScript* script);
void rss_read_info(RSScript* script);
int rss_set_cookie(RSScript* script, kvlist* cookie);
int rss_is_cookie_authed(RSScript* script);
stringptr* rss_create_auth_cookie(RSScript* script);
void rss_make_auth_cookie(RSScript* script);
void rss_set_cookie_authed(RSScript* script, stringptr* cookie);
stringptr* rss_get_ip(RSScript* script);
void rss_set_responsetype(RSScript* script, int rt);
void rss_set_contenttype(RSScript* script, stringptr* ct);
void rss_respond(RSScript* script, stringptr* msg);
void rss_submit(RSScript* script);
void rss_redirect_soft(RSScript* script, stringptr* newloc);
void rss_redirect_hard(RSScript* script, stringptr* newloc);
void rss_respond_quick(RSScript* script, stringptr* err);
void rss_respond500(RSScript* script);
void rss_respond404(RSScript* script);

#endif

//RcB: DEP "RSScript.c"
