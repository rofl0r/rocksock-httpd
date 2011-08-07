/*
 * author: rofl0r 
 * 
 * License: GPL v3 
 * 
 */
#undef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <sys/stat.h>

#include "RSScript.h"

#include "../../lib/include/strlib.h"
#include "../../lib/include/fileparser.h"
#include "../../lib/include/logger.h"

#ifndef IN_KDEVELOP_PARSER
//static const stringptr* failed_handle_msg = SPLITERAL("failed to get filehandle");
#ifndef COOKIE_DB
#error need to set COOKIE_DB to a pathname
#else
static const stringptr* authcookiedb = SPLITERAL(COOKIE_DB);
#endif
static const stringptr* tempfile_template = SPLITERAL("/tmp/XXXXXX");
static const stringptr* authtimeoutsecs_as_str = SPLITERAL("1800");
#endif
static int authtimeoutsecs = 30 * 60;
static const char RSS_EOUTOFMEM[] = "out of memory";

__attribute__ ((noreturn))
static void die(const char* s, int doperror) {
	if(doperror) log_perror((char*)s);
	else ulz_fprintf(2, "%s\n", s);
	exit(1);
}

void rss_init(RSScript* script, int argc, char** argv) {
	srand(time(NULL));
	umask(S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH); // umask _removes_ the bits. 
	if(argc < 4) {
		die("invalid argument count", 0);
	}
#ifdef DEBUG
	stringptr* dump = stringptr_fromfile(argv[1]);
	if(!dump) {
		die("ERROR, req file not found or unable to read", 1);
	}
	stringptr_tofile("last.req", dump);
	stringptr_free(dump);
#endif
	memset(script, 0, sizeof(RSScript));
	script->request_fn = argv[1];
	script->response_fn = argv[2];
	script->info_fn = argv[3];
	
	script->req.reqdata = kv_new(8);
	script->req.formdata = kv_new(8);
	script->req.getparams = kv_new(8);
	script->req.cookies = kv_new(8);
	script->info = kv_new(8);
	script->response_lines = stringptrlist_new(0);
}

static void my_kv_free(kvlist* l) {
	stringptrv* t;
	size_t i;
	if(!l) return;
	for(i = 0; i < kv_getsize(l); i++) {
		if((t = kv_get(l, i))) {
			free(t->ptr);
			if(t->value) stringptr_free((stringptr*) t->value);
		}
	}
	kv_free(l);
}

void rss_free(RSScript* script) {
	stringptr* temp;
	size_t i;
	my_kv_free(script->req.reqdata);
	my_kv_free(script->req.formdata);
	my_kv_free(script->req.getparams);
	my_kv_free(script->req.cookies);
	my_kv_free(script->info);
	if(script->req.upload_fn) stringptr_free(script->req.upload_fn);
	if(script->req.uri) stringptr_free(script->req.uri);
	for(i = 0; i < stringptrlist_getsize(script->response_lines); i++)
		if((temp = stringptrlist_get(script->response_lines, i)))
			free(temp->ptr);
		
	//if(script->response_contenttype) free(script->response_contenttype); //conttenttype is managed by caller and most likely a SPLITERAL
}

stringptr* url_encode(stringptr* url) {
	if(!url) return NULL;
	stringptr* result = stringptr_new(url->size * 3);
	if(!result) return NULL;
	result->size = 0;
	size_t i;
	for(i = 0; i < url->size; i++) {
		if(isAlpha(url->ptr + i)) {
			result->ptr[i] = url->ptr[i];
			result->size++;
		} else {
			ulz_snprintf(result->ptr + result->size, 4, "%%%.2X", url->ptr[i]);
			result->size += 3;
		}
	}
	return result;
}

stringptr* url_decode(stringptr* url) {
	if(!url) return NULL;
	stringptr* result = stringptr_new(url->size);
	if(!result) return NULL;
	result->size = 0;
	size_t i;
	i = 0;
	while(i < url->size) {
		switch(url->ptr[i]) {
			case '%':
				if(i + 2 < url->size) {
					i += 2;
					result->ptr[result->size] = (hexval(url->ptr + (i-1)) * 16) + hexval(url->ptr + i);
				}
				break;
			case '+':
				result->ptr[result->size] = ' ';
				break;
			default:
				result->ptr[result->size] = url->ptr[i];
		}
		i++;
		result->size++;
	}
	result->ptr[result->size] = 0;
	return result;
}

void rss_read_request(RSScript* script) {
	fileparser pz;
	fileparser* p = &pz;
	stringptr lb;
	stringptr* line = &lb;
	int doneheader = 0, i = 0;
	int ret;
	char* buf, *malbuf; size_t buflen;
	size_t k;
	int m1 = -1;
	size_t pos, pos2;
	char* s1, *max;
	char save;
	stringptr* rp, *key, *val;
	stringptrlist* kv, *kv2, *kv3;
	if(fileparser_open(p, script->request_fn)) die("file access", 1);
	while(!(ret = fileparser_readline(p)) || ret == -3) {
		malbuf = NULL;
		if(ret == -3) {
			buflen = fileparser_getnextlinelength(p);
			if((ssize_t) buflen <= 0) break;
			malbuf = malloc(buflen + 1);
			if(!malbuf) die(RSS_EOUTOFMEM, 1);
			buf = malbuf;
			if(fileparser_readline_userbuf(p, buf, buflen + 1)) {
				free(malbuf);
				break;
			}
		} else {
			buf = p->buf;
			buflen = p->len;
		}
		if(!doneheader)
			script->req.headersize += buflen + 1; // + cut off '\n' at the end
		if(doneheader)
			script->req.multishitheadersize += buflen + 1;
		if(buflen && buf[buflen -1] == '\r') {
			buflen -= 1;
			buf[buflen] = 0;
		}
		if(!buflen) {
			if(!doneheader) doneheader = 1;
			if(doneheader < 4) continue;
			break;
		}
		if(!i && buflen > 4 && (!(m1 = memcmp(buf, "GET ", 4)) || !memcmp(buf, "POST ", 5) )) {
			if(!m1) script->req.meth = RM_GET;
			else script->req.meth = RM_POST;
			pos = !m1 ? 4 : 5;
			line->ptr = buf + pos;
			s1 = line->ptr;
			max = line->ptr + (buflen - pos);
			while(s1 < max && *s1 && *s1 != '?' && *s1 != ' ') 
				s1++;
			if(s1 < max) {
				save = *s1;
				*s1 = 0;
				pos2 = (s1 - buf);
			}
			else {
				pos2 = buflen;
				save = 0;
			}
			line->size = pos2 - pos;
			script->req.uri = stringptr_copy(line);
			*s1 = save;
			if(*s1 == '?' && s1 < max && *(++s1)) {
				line->ptr = s1;
				while(s1 < max && *s1&& *s1 != ' ') s1++;
				if(s1 < max && *s1) {
					*s1 = 0;
					line->size = s1 - line->ptr;
					if((rp = url_decode(line))) {
						if((kv = stringptr_splitc(rp, '&'))) {
							for(k = 0; k < stringptrlist_getsize(kv); k++) {
								stringptr* baz;
								if((baz = stringptrlist_get(kv, k)) && (kv2 = stringptr_splitc(baz, '='))) {
									if((key = stringptrlist_get(kv2, 0)) && (val = stringptrlist_get(kv2, 1)) && (s1 = stringptr_strdup(key))) {
										kv_add(script->req.getparams, s1, key->size, stringptr_copy(val));
									}
									stringptrlist_free(kv2);
								}
							}
							stringptrlist_free(kv);
						}
						stringptr_free(rp);
					}
				}
			}
			goto le;
		}
		line->ptr = buf;
		line->size = buflen;
		if(i && !doneheader) {
			if((kv = stringptr_splits(line, SPLITERAL(": ")))) {
				val = stringptrlist_get(kv, 1);
				if((key = stringptrlist_get(kv, 0))) {
					if(stringptr_here(key, 0, SPLITERAL("Cookie"))) {
						if(val && (kv2 = stringptr_splitc(val, ';'))) {
							for(k = 0; k < stringptrlist_getsize(kv2); k++) {
								if((key = stringptrlist_get(kv2, k)) && key->size) {
									if(key->ptr[0] == ' ') stringptr_shiftright(key, 1);
									if((kv3 = stringptr_splitc(key, '='))) {
										if((key = stringptrlist_get(kv3, 0)) && (val = stringptrlist_get(kv3, 1))) {
											if((s1 = stringptr_strdup(key))) {
												kv_add(script->req.cookies, s1, key->size, stringptr_copy(val));
											}
										}
										stringptrlist_free(kv3);
									}
								}
							}
							stringptrlist_free(kv2);
						}
					} else {
						if((s1 = stringptr_strdup(key))) {
							kv_add(script->req.reqdata, s1, key->size, val ? stringptr_copy(val) : NULL);
						}
					}
				}
				stringptrlist_free(kv);
			}
		} else if (doneheader == 1) {
			if(script->req.meth == RM_POST && (
					(kv_find(script->req.reqdata, SPLITERAL("Content-Type"), (void**) &key)) ||
					(kv_find(script->req.reqdata, SPLITERAL("Content-type"), (void**) &key))
			)){
				if(stringptr_here(key, 0, SPLITERAL("application/x-www-form-urlencoded"))) {
				//if(strstr(key->ptr, "form-urlencoded")) {
					if((kv = stringptr_splitc(line, '&'))) {
						for(k = 0; k < stringptrlist_getsize(kv); k++) {
							if((key = stringptrlist_get(kv, k)) && (kv2 = stringptr_splitc(key, '='))) {
								if((key = stringptrlist_get(kv2, 0)) && (rp = url_decode(key))) {
									 val = stringptrlist_get(kv2, 1);
									 if((s1 = stringptr_strdup(rp)))
										kv_add(script->req.formdata, s1, rp->size, val ? url_decode(val) : NULL);
									 stringptr_free(rp);
								}
								stringptrlist_free(kv2);
							}
						}
						stringptrlist_free(kv);
					}
				} else if((s1 = strstr(key->ptr, "multipart/form-data; boundary="))) {
					s1 += 30;
					if(stringptr_shiftright(key, s1 - key->ptr)) {
						while((s1 < key->ptr + key->size) && (*s1 == '-' || *s1 == '_' || isAlpha(s1)))
							s1++;
						*s1 = 0;
						key->size = s1 - key->ptr;
						script->req.boundary = stringptr_copy(key);
					}
					doneheader = 2;
				} else
					break;
			}
			
		} else if (doneheader == 2) {
			if(line->size && (s1 = strstr(line->ptr, "filename=\""))) {
				s1 += 10;
				line->size -= (s1 - line->ptr);
				line->ptr = s1;
				while((s1 < line->ptr + line->size) && *s1 && *s1 != '"')
					s1++;
				*s1 = 0;
				line->size = s1 - line->ptr;
				script->req.upload_fn = stringptr_copy(line);
				doneheader = 3;
			}
		} else if (doneheader == 3) {
			if(line->size && strstr(line->ptr, "Content-Type"))
				doneheader = 4;
		}
		le:
		i++;
		if(malbuf) free(malbuf);
	}
	fileparser_close(p);
}

// you should have a *very* good reason to pass NULL as outname (that means the client can choose the filename)
void rss_write_attachment(RSScript* script, stringptr* outname) {
	FILE *in, *out;
	size_t fpos, maxpos;
	size_t written;
	stringptr* s;
	char buf[1024];
	if(!outname && (!script->req.upload_fn || !script->req.upload_fn->size)) return;
	if(!outname && strstr(script->req.upload_fn->ptr, "..")) {
		ulz_fprintf(2, "directory traversal try detected\n");
		return;
	}
	if (!outname) outname = script->req.upload_fn;
	if((in = fopen(script->request_fn, "r"))) {
		if((out = fopen(outname->ptr, "w"))) {
			if(script->req.boundary && (kv_find(script->req.reqdata, SPLITERAL("Content-Length"), (void**)&s))) {
				fpos = script->req.headersize + script->req.multishitheadersize;
				//it seems we have at the end: \r\n--BOUNDARY--\r\n according to RFC1341
				maxpos = script->req.headersize + atol(s->ptr) - (2 + 2 + script->req.boundary->size + 2 + 2);
				if(maxpos > fpos && !fseek(in, fpos, SEEK_SET)) {
					do {
						written = fread(buf, 1, sizeof(buf), in);
						if(fpos + written > maxpos)
							written = maxpos - fpos;
						fpos += written;
						written = fwrite(buf, 1, written, out);
					} while(fpos < maxpos && written);
				}
			}
			fclose(out);
		}
		fclose(in);
	}
}

rss_http_request* rss_get_request(RSScript* script) {
	if(!script->req.headersize)
		rss_read_request(script);
	return &script->req;
}

void rss_read_info(RSScript* script) {
	fileparser pz;
	fileparser* p = & pz;
	stringptr lp;
	stringptr* line = &lp;
	stringptrlist* kv;
	char* c;
	stringptr *key, *value;
	if(!(fileparser_open(p, script->info_fn))) {
		while(!(fileparser_readline(p))) {
			line->ptr = p->buf;
			line->size = p->len;
			stringptr_chomp(line);
			if(!line->size) continue;
			if((kv = stringptr_splits(line, SPLITERAL(": ")))) {
				if((key = stringptrlist_get(kv, 0)) && (value = stringptrlist_get(kv, 1)) && key->size && (c = stringptr_strdup(key)))
					kv_add(script->info, c, key->size, stringptr_copy(value));
			}
		}
		fileparser_close(p);
	}
}


/*
expecting a kvlist as cookie, like:
{ name => "foo", value => "bar", "Max-Age" => 600, "Path" => "/", "Domain" => ".example.com", "HttpOnly" => NULL }
other possible fields: "Expires" => "Wed, 13-Jan-2021 22:23:01 GMT" "Secure" => undef
set value => "deleted" and/or Max-Age to 0 to delete the cookie
 */
int rss_set_cookie(RSScript* script, kvlist* cookie) {
	if(! script || ! cookie || script->response_cookie_count == sizeof(script->response_cookies)) return 0;
	script->response_cookies[script->response_cookie_count++] = cookie;
	return 1;
}

int rss_is_cookie_authed(RSScript* script) {
	rss_http_request* req;
	stringptr* s;
	fileparser pv;
	fileparser *p = &pv;
	stringptr lb, *line = &lb, *key, *val;
	stringptrlist* kv;
	time_t timeout;
	int res = 0;

	if(!(req = rss_get_request(script))) return 0;
	if(!kv_find(script->req.cookies, SPLITERAL("auth"), (void**)&s)) return 0;
	if(!fileparser_open(p, authcookiedb->ptr)) {
		while(!fileparser_readline(p) && !fileparser_getline(p, line)) {
			stringptr_chomp(line);
			if((kv = stringptr_splitc(line, '|'))) {
				if((key = stringptrlist_get(kv, 0)) && (val = stringptrlist_get(kv, 1))) {
					timeout = atol(key->ptr);
					if(stringptr_eq(s, val) && timeout > time(NULL)) {
						res = 1;
						goto finish;
					}
				}
				stringptrlist_free(kv);
			}
		}
		finish:
		fileparser_close(p);
	}
	return res;
}

// generates a 64bit random cookie for auth
stringptr* rss_create_auth_cookie(RSScript* script) {
	stringptr* res = stringptr_new(16);
	if(!res) return NULL;
	(void) script;
	ulz_snprintf(res->ptr, 17, "%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X", 
		 rand() % 256, rand() % 256, rand() % 256, rand() % 256,
		 rand() % 256, rand() % 256, rand() % 256, rand() % 256);
	return res;
}

// make a valid cookie and add to response struct
static int rss_add_authed_cookie(RSScript* script, stringptr* cookie) {
	stringptrv* test;
	kvlist* lcookie;
	size_t i;
	if(!cookie || !(lcookie = kv_new(8))) return 0;
	kv_add(lcookie, strdup("name"), 4, stringptr_copy(SPLITERAL("auth")));
	kv_add(lcookie, strdup("value"), 5, cookie);
	kv_add(lcookie, strdup("Max-Age"), 7, stringptr_copy((stringptr*)authtimeoutsecs_as_str));
	kv_add(lcookie, strdup("Path"), 4, stringptr_copy(SPLITERAL("/")));
	for(i = 0; i < kv_getsize(lcookie); i++)
		if((test = kv_get(lcookie, i)) && (!test->ptr || !test->value))
			die(RSS_EOUTOFMEM, 0);
	rss_set_cookie(script, lcookie);
	return 1;
}

static void rss_set_cookie_authdb_entry(RSScript* script, stringptr* authcookie) {
	FILE *tmp; int temp;
	fileparser pv, *p = &pv;
	stringptr fcc, *fc = &fcc;
	stringptr *timeout, *fcookie;
	stringptrlist* kv;
	char buf[24];
	char tmpname[24];
	int done = 0;

	if(tempfile_template->size + 1 > sizeof(tmpname)) die("temp filename exceeds bufsize", 0);
	memcpy(tmpname, tempfile_template->ptr, tempfile_template->size+1);
	if((temp = mkstemp(tmpname)) == 1 || !(tmp = fdopen(temp, "w"))) die("cannot make tempfile", 1);
	if((fileparser_open(p, authcookiedb->ptr))) p = NULL;
	if(p) {
		while((!fileparser_readline(p)) && (!fileparser_getline(p, fc))) {
			stringptr_chomp(fc);
			if((kv = stringptr_splitc(fc, '|'))) {
				if((timeout = stringptrlist_get(kv, 0)) && (fcookie = stringptrlist_get(kv,1))) {
					if(stringptr_eq(authcookie, fcookie)) {
						writeself:
						fwrite(buf, 1, ulz_snprintf(buf, sizeof(buf), "%ld|", time(NULL) + authtimeoutsecs), tmp);
						fwrite(authcookie->ptr, 1, authcookie->size, tmp);
						done = 1;
					} else {
						fwrite(fc->ptr, 1, fc->size, tmp);
					}
				} else 
					continue;
				fwrite("\n", 1, 1, tmp);
				if(!kv) goto jumpback;
				stringptrlist_free(kv);
			}
		}
		fileparser_close(p);
	}
	if(!done) {
		kv = NULL;
		goto writeself;
	}
	jumpback:
	fclose(tmp);
	rename(tmpname, authcookiedb->ptr);
}

// this is the func to be called from userland. sets the db entry AND the entry in the submit struct
void rss_set_cookie_authed(RSScript* script, stringptr* cookie) {
	stringptr* authcookie;
	rss_http_request* req;
	if(!cookie) {
		req = rss_get_request(script);
		if(!kv_find(req->cookies, SPLITERAL("auth"), (void**) &authcookie)) die("authcookie not set!", 0);
	} else 
		authcookie = cookie;	
	rss_set_cookie_authdb_entry(script, authcookie);
	rss_add_authed_cookie(script, authcookie);
}

/*
this is the function that CREATES a NEW cookie. use only on successfull login
additionally it adds it to the response struct and the db
*/
void rss_make_auth_cookie(RSScript* script) {
	stringptr* cookie = rss_create_auth_cookie(script);
	if(!cookie || !rss_add_authed_cookie(script, cookie)) return;
	rss_set_cookie_authdb_entry(script, cookie);
}

static stringptr* rss_get_info_entry(RSScript* script, stringptr* entry) {
	if(!kv_getsize(script->info)) rss_read_info(script);
	stringptr* result;
	return kv_find(script->info, entry, (void**) &result) ? result : NULL;
}

stringptr* rss_get_ip(RSScript* script) {
	return rss_get_info_entry(script, SPLITERAL("IP"));
}

stringptr* rss_get_docroot(RSScript* script) {
	return rss_get_info_entry(script, SPLITERAL("DR"));
}

void rss_set_responsetype(RSScript* script, int rt) {
	switch(rt) {
		case 404: case 500: case 200: case 307:
			script->response_err = rt;
			break;
		default:
			die("unimplemented responsetype", 0);
	}
}

// contenttype will be freed by sender
void rss_set_contenttype(RSScript* script, stringptr* ct) {
	if(!script) return;
	script->response_contenttype = ct;
}

void rss_respond(RSScript* script, stringptr* msg) {
	char* p2;
	if(!script->response_err) die("need to set responsetype before respond()!", 0);
	if(!msg || !msg->ptr || !msg->size) return;
	if(!(p2 = stringptr_strdup(msg))) return;
	if(stringptrlist_add(script->response_lines, p2, msg->size)) script->response_len += msg->size;
	return;
}

static void checked_write(const char* buf, size_t c, size_t n, FILE* f) {
	if(fwrite(buf, c, n, f) != c * n)
		die("failed to write response file", 1);
}

void rss_submit(RSScript* script) {
#ifndef IN_KDEVELOP_PARSER
	stringptr* err404 = SPLITERAL("HTTP/1.1 404 Not found\r\nContent-Type: text/html\r\nContent-Length: 3\r\n\r\n404");
	stringptr* err500 = SPLITERAL("HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/html\r\nContent-Length: 5\r\n\r\nError");
	stringptr* err200 = SPLITERAL("HTTP/1.1 200 OK\r\nContent-Type: ");
#endif
	static const char* rn = "\r\n";
	stringptr* which, *val;
	size_t i, j;
	kvlist* kv;
	stringptr* rp;
	stringptrv *a;
	char buf[24];
	
	if(!script->response_err) die("need to set responsetype before respond()!", 0);
#ifdef DEBUG
	fprintf(stderr, "opening %s for output\n", script->response_fn);
#endif
	FILE *out;
	if(!(out = fopen(script->response_fn, "w"))) die("failed to open response file", 1);
	if(script->response_err == 404 || script->response_err == 500) {
		if(script->response_err == 404) which = err404;
		else which = err500;
		checked_write(which->ptr, 1, which->size, out);
		fclose(out);
		return;
	}
	if(!script->response_contenttype) script->response_contenttype = SPLITERAL("text/html");
	checked_write(err200->ptr, 1, err200->size, out);
	checked_write(script->response_contenttype->ptr, 1, script->response_contenttype->size, out);
	checked_write(rn, 1, 2, out);
	
	for(i = 0; i < script->response_cookie_count; i++) {
		kv = script->response_cookies[i];
		if(!kv_find(kv, SPLITERAL("name"), (void**)&which) || !kv_find(kv, SPLITERAL("value"), (void**)&val)) die ("cookie without name or value, invalid!", 0);
		rp = url_encode(val);
		checked_write("Set-Cookie: ", 1, 12, out);
		checked_write(which->ptr, 1, which->size, out);
		checked_write("=", 1, 1, out);
		checked_write(rp->ptr, 1, rp->size, out);
		checked_write("; ", 1, 2, out);
		for(j = 0; j < kv_getsize(kv); j++) {
			a = kv_get(kv, j);
			if(stringptr_eq((stringptr*) a, SPLITERAL("name")) || stringptr_eq((stringptr*) a, SPLITERAL("value"))) continue;
			checked_write(a->ptr, 1, a->size, out);
			if(a->value) {
				checked_write("=", 1, 1, out);
				checked_write(((stringptr*)(a->value))->ptr, 1, ((stringptr*)(a->value))->size, out);
			}
			checked_write("; ", 1, 2, out);
		}
		checked_write(rn, 1, 2, out);
	}
	checked_write("Content-Length: ", 1, 16, out);
	checked_write(buf, 1, ulz_snprintf(buf, sizeof(buf), "%zu\r\n\r\n", script->response_len), out);
	for(i = 0; i < stringptrlist_getsize(script->response_lines); i++) {
		if((which = stringptrlist_get(script->response_lines, i)))
			checked_write(which->ptr, 1, which->size, out);
	}
	fclose(out);
	return;
}

//since redirect with post data makes browsers ask lame questions about reposting
void rss_redirect_soft(RSScript* script, stringptr* newloc) {
	stringptr* out;
	if(!newloc) return;
	rss_set_responsetype(script, 200);
	rss_set_contenttype(script, SPLITERAL("text/html"));
	if((out = stringptr_concat(SPLITERAL("<html><META HTTP-EQUIV=\"Refresh\" CONTENT=\"1;URL="), newloc, SPLITERAL("\"></html>"), NULL)))
		rss_respond(script, out);
	else die(RSS_EOUTOFMEM, 0);
	rss_submit(script);
}

void rss_redirect_hard(RSScript* script, stringptr* newloc) {
	stringptr* out;
	if(!newloc) return;
	FILE* fout;
	if(!(fout = fopen(script->response_fn, "w"))) die("could not open resp. file", 1);
	if((out = stringptr_concat(SPLITERAL("HTTP/1.1 307 Moved temporary\r\nLocation: "), newloc, SPLITERAL("\r\nContent-Type: text/html\r\nContent-Length: 3\r\n\r\n307"), NULL)))
		fwrite(out->ptr, 1, out->size, fout);
	fclose(fout);
}

void rss_respond_quick(RSScript* script, stringptr* err) {
	FILE* fout;
	if(!(fout = fopen(script->response_fn, "w"))) die("could not open resp. file", 1);
	fwrite(err->ptr, 1, err->size, fout);
	fclose(fout);
}

void rss_respond500(RSScript* script) {
	stringptr* err = SPLITERAL("HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/html\r\nContent-Length: 3\r\n\r\n500");
	rss_respond_quick(script, err);
}

void rss_respond404(RSScript* script) {
	stringptr* err = SPLITERAL("HTTP/1.1 404 Not Found\r\nContent-Type: text/html\r\nContent-Length: 3\r\n\r\n404");
	rss_respond_quick(script, err);
}

