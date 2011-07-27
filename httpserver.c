/*
    Copyright (C) 2010-2011  rofl0r

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
    
 */


#include <sys/select.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include <fcntl.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <grp.h>

#include "../rocksock/rocksockserver.h"
#include "../lib/include/stringptr.h"
#include "../lib/include/strlib.h"
#include "../lib/include/filelib.h"
#include "../lib/include/optparser.h"
#include "../lib/include/logger.h"

static const char content_type_text_html[] = "text/html";
static const char content_type_text_plain[] = "text/plain";
static const char content_type_binary_octet_stream[] = "binary/octet-stream";
static const char content_type_image_jpeg[] = "image/jpeg";
static const char content_type_image_gif[] = "image/gif";
static const char content_type_image_png[] = "image/png";
static const char content_type_application_pdf[] = "application/pdf";


static const char file_type_htm[] = "htm";
static const char file_type_html[] = "html";
static const char file_type_perl[] = "pl\0\0";
static const char file_type_sh[] = "sh\0\0";
static const char file_type_txt[] = "txt";
static const char file_type_gif[] = "gif";
static const char file_type_jpeg[] = "jpeg";
static const char file_type_jpg[] = "jpg";
static const char file_type_png[] = "png";
static const char file_type_cgi[] = "cgi";
static const char file_type_pdf[] = "pdf";

typedef struct {
	const char* fileext;
	const char* content_type;
} contenttype;

static const contenttype typemap[] = {
	{ file_type_htm, content_type_text_html },
	{ file_type_html, content_type_text_html },
	{ file_type_perl, content_type_text_plain },
	{ file_type_sh, content_type_text_plain },
	{ file_type_txt, content_type_text_plain },
	{ file_type_gif, content_type_image_gif },
	{ file_type_jpeg, content_type_image_jpeg },
	{ file_type_jpg, content_type_image_jpeg },
	{ file_type_png, content_type_image_png },
	{ file_type_pdf, content_type_application_pdf },
	{ NULL, NULL }
};

typedef enum {
	CLIENT_DISCONNECTED = 0,
	CLIENT_CONNECTED = 1,
	CLIENT_READING = 2,
	CLIENT_WRITING = 4,
} clientstatus;

typedef enum {
	RQT_NONE = 0,
	RQT_GET,
	RQT_POST,
} requesttype;

typedef enum {
	ST_NONE = 0,
	ST_PERL,
} scripttype;

typedef struct {
	requesttype rqt;
	size_t streampos;
	char uri[1024];
	size_t urilength;
	size_t contentlength;
} clientrequest;

typedef enum {
	CL_NONE = 0,
	CL_KEEP_ALIVE = 1,
	CL_NEEDS_TURBO = 2
} clientflags;

typedef struct {
	clientstatus status;
	clientflags flags;
	FILE* requeststream;
	size_t requestsize;
	FILE* responsestream_header;
	FILE* responsestream;
	FILE* act_responsestream;
} httpclient;

#if (! defined(USER_BUFSIZE_KB)) || (USER_BUFSIZE_KB > 1024)
#define USER_BUFSIZE_KB 96
#endif

typedef struct {
	char buffer[USER_BUFSIZE_KB*1024]; 
	/* with buffersize 96K we can deliver a smoking ~75MB/s in turbomode. 
	 * bigger values doesnt seem to improve performance. maybe my hdd's were the bottleneck.
	 * 16K is sufficient for a 100Mbit line.
	 */
	char pathbuf[256];
	char tempdir[256];
	stringptr workdir;
	stringptr servedir;
	httpclient clients[USER_MAX_FD];
	rocksockserver serva;
	size_t maxrequestsize;
	time_t timeoutsec;
	unsigned turbo;
	unsigned numclients;
	int log;
} httpserver;

// client is requesting big data
void httpserver_turbomode(httpserver* self, int client) {
	if(!(self->clients[client].flags & CL_NEEDS_TURBO)) {
		self->turbo++;
		self->clients[client].flags |= CL_NEEDS_TURBO;
		rocksockserver_set_sleeptime(&self->serva, 500);
	}
}

// client connected, but not sending/receiving big amounts of data
void httpserver_idlemode(httpserver* self, int client) {
	if(self->clients[client].flags & CL_NEEDS_TURBO) {
		self->turbo--;
		self->clients[client].flags &= ~CL_NEEDS_TURBO;
	}
	if(!self->turbo)
		rocksockserver_set_sleeptime(&self->serva, 5000);
}

const char* httpserver_get_contenttype(char* filename, char* fileext) {
	size_t i;
	unsigned char fe[16] = {0};
	unsigned char* fex = (unsigned char*) fileext;
	FILE* temp;
	
	for (i = 0; i < 4; i++) {
		if(!fex[i]) break;
		fe[i] = fex[i];
	}
	i = 0;
	while(typemap[i].fileext) {
		if(!memcmp(fe, typemap[i].fileext, 4))
			return typemap[i].content_type;
		i++;
	}
	if(!(temp = fopen(filename, "r"))) 
		return content_type_text_plain;
	
	i = fread(fe, 1, sizeof(fe), temp);
	fclose(temp);
	
	if(i < sizeof(fe))
		return content_type_binary_octet_stream;
	
	for(i=0; i < sizeof(fe); i++)
		if(fe[i] < 9 || fe[i] > 127)
			return content_type_binary_octet_stream;
		
	return content_type_text_plain;	
}

__attribute__ ((noreturn))
void httpserver_handle_pathbuf_size(void) {
	ulz_fprintf(2, "%s", "FATAL: filename on tempfs exceeding 256 bytes\n");
	exit(1);
}

char* httpserver_get_client_requeststream_fn(httpserver* self, int client) {
	if(ulz_snprintf(self->pathbuf, sizeof(self->pathbuf), "%s/%d.requ", self->workdir.ptr, client) >= (int) sizeof(self->pathbuf))
		httpserver_handle_pathbuf_size();
	return self->pathbuf;
}

char* httpserver_get_client_responsestream_fn(httpserver* self, int client) {
	if(ulz_snprintf(self->pathbuf, sizeof(self->pathbuf), "%s/%d.resp", self->workdir.ptr, client) >= (int) sizeof(self->pathbuf))
		httpserver_handle_pathbuf_size();
	return self->pathbuf;
}

char* httpserver_get_client_infostream_fn(httpserver* self, int client) {
	if(ulz_snprintf(self->pathbuf, sizeof(self->pathbuf), "%s/%d.info", self->workdir.ptr, client) >= (int) sizeof(self->pathbuf))
		httpserver_handle_pathbuf_size();
	return self->pathbuf;
}

char* httpserver_get_client_ip(httpserver* self, struct sockaddr_storage* ip) {
	if(ip->ss_family == PF_INET)
	return (char*) inet_ntop(PF_INET, &((struct sockaddr_in*) ip)->sin_addr, self->buffer, sizeof(self->buffer));
	else return (char*) inet_ntop(PF_INET6, &((struct sockaddr_in6*) ip)->sin6_addr, self->buffer, sizeof(self->buffer));
}

// doclose: 1: close conn, 0: client already disconnected, -1: init only
#ifdef DISCONNECT_DEBUG
int httpserver_disconnect_client(httpserver* self, int client, int doclose, int line, const char* file, const char* function) {
#else
int httpserver_disconnect_client(httpserver* self, int client, int doclose) {
#endif
	if(doclose != -1 && self->log)
#ifdef DISCONNECT_DEBUG
		ulz_fprintf(1, "[%d] disconnecting client (%s.%s:%d) - forced: %d\n", client, file, function, line, doclose);
#else
		ulz_fprintf(1, "[%d] disconnecting client - forced: %d\n", client, doclose);
#endif
	if(self->clients[client].responsestream_header) {
		fclose(self->clients[client].responsestream_header);
		self->clients[client].responsestream_header = NULL;
	}
	if(self->clients[client].responsestream) {
		fclose(self->clients[client].responsestream);
		self->clients[client].responsestream = NULL;
	}
	self->clients[client].act_responsestream = NULL;
	if(self->clients[client].requeststream) {
		fclose(self->clients[client].requeststream);
		self->clients[client].requeststream = NULL;
	}
	
	self->clients[client].requestsize = 0;
	unlink(httpserver_get_client_infostream_fn(self, client));
	unlink(httpserver_get_client_requeststream_fn(self, client));
	unlink(httpserver_get_client_responsestream_fn(self, client));
	if(doclose == 1) 
		rocksockserver_disconnect_client(&self->serva, client);
	if(doclose == 1 || !doclose) {
		self->numclients--;
		httpserver_idlemode(self, client);
	}
	
	self->clients[client].status = CLIENT_DISCONNECTED;
	self->clients[client].flags = CL_NONE;
	return 0;
}
#ifdef DISCONNECT_DEBUG
#define _httpserver_disconnect_client(x, y, z) httpserver_disconnect_client(x, y, z, __LINE__, __FILE__, __FUNCTION__);
#else
#define _httpserver_disconnect_client(x, y, z) httpserver_disconnect_client(x, y, z);
#endif

int httpserver_on_clientconnect (void* userdata, struct sockaddr_storage* clientaddr, int fd) {
	static const char ip_msg[] = "IP: ";
	static const size_t ip_msg_l = sizeof(ip_msg) - 1;
	static const char dr_msg[] = "DR: ";
	static const size_t dr_msg_l = sizeof(dr_msg) - 1;
	httpserver* self = (httpserver*) userdata;
	FILE* info;
	unsigned fail = 0;
	size_t len;
	
	if(fd < 0) return -1;
	if(fd >= USER_MAX_FD) {
		close(fd);
		return -2;
	}
	// put into nonblocking mode, so that writes will not block the server
	int flags = fcntl(fd, F_GETFL); 
	if(flags == -1) return -1;
	if(fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) return -2;
	self->numclients++;
	_httpserver_disconnect_client(self, fd, -1); // make a clean state and delete the files. this is important for the timeout check.
	self->clients[fd].status = CLIENT_CONNECTED;
	if(httpserver_get_client_infostream_fn(self, fd) && httpserver_get_client_ip(self, clientaddr) && (info = fopen(self->pathbuf, "w+"))) {
		if((len = strlen(self->buffer)) && len < sizeof(self->buffer) -1) {
			self->buffer[len] = '\n';
			len++;
			self->buffer[len] = 0;
		} else fail = 1;
		if(!fail && (
			(fwrite(ip_msg, 1, ip_msg_l, info) < ip_msg_l) ||
			(fwrite(self->buffer, 1, len, info) < len) ||
			(fwrite(dr_msg, 1, dr_msg_l, info) < dr_msg_l) ||
			(fwrite(self->servedir.ptr, 1, self->servedir.size, info) < self->servedir.size)
		)) fail = 1;
		fclose(info);
		if(fail) {
			if(self->log)
				ulz_fprintf(1, "[%d] error writing info file\n", fd);
			close(fd);
			return -3;
		}
		if(self->log)
			ulz_fprintf(1, "[%d] Connect from %s\n", fd, self->buffer);
	}
	return 0;
}

// returns 1 if clients has reached timeout
int httpserver_check_timeout(httpserver* self, int client) {
	time_t ret;
	if((ret = getFileModTime(httpserver_get_client_requeststream_fn(self, client))) && (ret + self->timeoutsec) < time(NULL))
		return 1;
	return 0;
}

int httpserver_on_clientwantsdata (void* userdata, int fd) {
	httpserver* self = (httpserver*) userdata;
	size_t nread;
	ssize_t nwritten;
	int err;
	if(!self->clients[fd].act_responsestream)
		self->clients[fd].act_responsestream = self->clients[fd].responsestream_header;
	if(self->clients[fd].status == CLIENT_WRITING) {
		if(!self->clients[fd].act_responsestream) {
			goto checkdisconnect;
		}
		if(feof(self->clients[fd].act_responsestream)) {
			fclose(self->clients[fd].act_responsestream);
			if(self->clients[fd].act_responsestream == self->clients[fd].responsestream_header) {
				self->clients[fd].responsestream_header = NULL;
				self->clients[fd].act_responsestream = self->clients[fd].responsestream;
			} else {
				self->clients[fd].responsestream = NULL;
				self->clients[fd].act_responsestream = NULL;
				checkdisconnect:
				if(self->clients[fd].flags & CL_KEEP_ALIVE) {
					self->clients[fd].status = CLIENT_CONNECTED;
					httpserver_idlemode(self, fd);
				}	
				else
					_httpserver_disconnect_client(self, fd, 1);
			}	
		} else {
			nread = fread(self->buffer, 1, sizeof(self->buffer), self->clients[fd].act_responsestream);
			if(!nread) return 4;
			nwritten = write(fd, self->buffer, nread);
			if(nwritten == -1) {
				err = errno;
				if(err == EAGAIN || err == EWOULDBLOCK) nwritten = 0;
				else {
					if(err != EBADF) self->clients[fd].act_responsestream = NULL;
					perror("writing");
					_httpserver_disconnect_client(self, fd, 0);
					return 3;
				}
			}
			if((size_t) nwritten < nread) fseek(self->clients[fd].act_responsestream, -(nread - nwritten), SEEK_CUR);
		}
	} else if ((self->clients[fd].status == CLIENT_CONNECTED || self->clients[fd].status == CLIENT_READING) && 
			(!(rand() % 1000) && httpserver_check_timeout(self, fd))
		) {
		_httpserver_disconnect_client(self, fd, 1);
	}
	return 1;
}

//parses the request, returns -1 if invalid, 0 if not complete, 1 if complete.
// if complete, the clientrequest member will be filled.
int httpserver_request_header_complete(httpserver* self, int client, clientrequest* req) {
	static const char CL_LIT[] = "Content-*ength: ";
	static const size_t CL_LITS = sizeof(CL_LIT) - 1;
	size_t nread;
	size_t len;
	int done = 0;
	char* p;
	
	memset(req, 0, sizeof(clientrequest));
	rewind(self->clients[client].requeststream);

	#define access_ok(x) ((x) - self->buffer < (ptrdiff_t) nread)
	#define checkrnrn (access_ok(p+3) && *p == '\r' && p[1] == '\n' && p[2] == '\r' &&  p[3] == '\n')

	do {
		nread = fread(self->buffer, 1, sizeof(self->buffer), self->clients[client].requeststream);
		// set zero termination, to prevent atoi and strstr going out of bounds.
		if(nread == sizeof(self->buffer)) {
			self->buffer[sizeof(self->buffer) -1] = '\0';
		} else {
			self->buffer[nread] = '\0';
		}
		p = self->buffer;
		if(req->rqt == RQT_NONE) {
			if(!nread || (*p != 'G' && *p != 'P')) return -1; // invalid request, we only accept GET and POST.
			if (nread <= 5) return 0;
			if(*p == 'G' && p[1] == 'E' && p[2] == 'T' && p[3] == ' ') {
				req->rqt = RQT_GET;
				p += 4;
			} else if (*p == 'P' && p[1] == 'O' && p[2] == 'S' && p[3] == 'T' && p[4] == ' ') {
				req->rqt = RQT_POST;
				p += 5;
			} else return -1;
		}
		req->streampos = p - self->buffer;
		while(access_ok(++p) && *p != '\r');
		// search for URI.
		if(access_ok(p) && *p == '\r') {
			*p = 0;
			len = ((p - self->buffer) - req->streampos);
			if(len + 1 > sizeof(req->uri))
				return -1;
			memcpy(req->uri, self->buffer + req->streampos, len+1);
			req->urilength = len;
			*p = '\r';
		} else {
			check_invalid_or_incomplete:
			if(nread == sizeof(self->buffer)) // if we can't find a valid header in a full buffer
				return -1;
			return 0;
		}
		// p is pointing to the first \r at this point.
		if(checkrnrn) {
			req->streampos = (p - self->buffer) + 3;
			return 1;
		}
		p++;
		req->streampos = p - self->buffer;
		while(access_ok(p) && !checkrnrn) p++;
		if(!access_ok(p)) {
			goto check_invalid_or_incomplete;
		}
		// search for content-length.
		len = req->streampos; // len points to the end of the GET/POST line.
		req->streampos = (p - self->buffer) + 4;
		*p = 0;
		if(len == nread) return -1; // just to be sure...
		if(req->rqt == RQT_POST) {
			//if(( p = strstr(self->buffer + len, "Content-Length: "))) { // THANX LYNX for "Content-length"
			if(( p = strstar(self->buffer + len, CL_LIT, CL_LITS))) {
				if(access_ok(p + CL_LITS + 1)) {
					p += CL_LITS;
					req->contentlength = atoi(p);
				} else return -1;
			}
		}
		// search for keep-alive
		if(( p = strstr(self->buffer + len, "Connection: "))) {
			p += 12;
			if(access_ok(p+10) && (!memcmp(p, "Keep-Alive", 10) || !memcmp(p, "keep-alive", 10)))
				self->clients[client].flags |= CL_KEEP_ALIVE;
		}
		return 1;
		
	} while (!done && nread == sizeof(self->buffer));
	
	return 0;
	#undef access_ok
	#undef checkrnrn
}

int httpserver_get_filename(httpserver* self, clientrequest* req) {
	static const char index_html[] = "index.html";
	static const size_t index_html_l = sizeof(index_html);
	char* p = req->uri;
	size_t vlen = 0;
	while (*p && *p != '?' && *p != ' ') p++;
	req->urilength = p - req->uri;
	*p = 0;
	if(!req->urilength
#ifdef ALLOW_TRAVERSAL
#warning this is a dangerous flag and should only be set for testing!
#else
		|| strstr(req->uri, "..")
#endif
	) return -1;
	vlen = (p[-1] == '/') ? index_html_l : 0;
	if(self->servedir.size + req->urilength + vlen >= sizeof(self->pathbuf)) return -2;
	memcpy(self->pathbuf, self->servedir.ptr, self->servedir.size);
	memcpy(self->pathbuf + self->servedir.size, req->uri, req->urilength + 1);
	if(vlen) memcpy(self->pathbuf + self->servedir.size + req->urilength, index_html, vlen+1);
	return 0;
}

int httpserver_spawn(httpserver* self, char* script, int client, scripttype stype) {
	char scriptcp[256];
	char reqfn[256];
	char infofn[256];
	pid_t pid;
	int ret;
	(void) stype;
	strncpy(scriptcp, script, sizeof(scriptcp));
	httpserver_get_client_infostream_fn(self, client);
	strncpy(infofn, self->pathbuf, sizeof(infofn));
	httpserver_get_client_requeststream_fn(self, client);
	strncpy(reqfn, self->pathbuf, sizeof(reqfn));
	httpserver_get_client_responsestream_fn(self, client);
	pid = fork();
	if(!pid) {
		execl(scriptcp, scriptcp, reqfn, self->pathbuf, infofn, NULL);
	} else if(pid < 0) perror("failed to fork");
	else {
		wait(&ret);
	}
	if(ret && self->log)
		strncpy(self->pathbuf, scriptcp, sizeof(self->pathbuf));
	return ret;
}

int httpserver_deliver(httpserver* self, int client, clientrequest* req) {
	static const char err500[] = "HTTP/1.1 500 Fuck you\r\nContent-Type: text/html\r\nContent-Length: 15\r\n\r\n500 - Fuck You.";
	static const size_t err500l = sizeof(err500);
	static const char err404[] = "HTTP/1.1 404 Not found\r\nContent-Type: text/html\r\nContent-Length: 3\r\n\r\n404";
	static const size_t err404l = sizeof(err404);
	static const char err200[] = "HTTP/1.1 200 OK\r\nContent-Type: %s\r\nContent-Length: %d\r\n\r\n";
	//static const size_t err200l = sizeof(err200);
	
	size_t len;
	int ret = 0;
	int res;
	char* rh = NULL;
	size_t rl;
	char* fe;
	scripttype st = ST_NONE;
	
	self->clients[client].status = CLIENT_WRITING;
	httpserver_idlemode(self, client);
	
#define respond(x, y, z) do {rh = (char*) x; rl = y; res = z; goto writeheader;} while (0);
	
	if(req) 
		ret = httpserver_get_filename(self, req);
	
	if(!req || ret) 
		respond(err500, err500l, 1);
	
	if(access(self->pathbuf, R_OK) == -1) 
		respond(err404, err404l, 2);
	
	fe = getFileExt(self->pathbuf, strlen(self->pathbuf));
	if(!memcmp(fe, "pl", 2) || !memcmp(fe, "cgi", 3)) {
		if(access(self->pathbuf, X_OK) == -1) {
			if(self->log)
				ulz_fprintf(1, "[%d] script %s not executable\n", client, self->pathbuf);
			respond(err404, err404l, 2);
		}	
		st = ST_PERL;
		goto runscript;
		runscript:
		ret = httpserver_spawn(self, self->pathbuf, client, st);
		if(ret && self->log)
			ulz_fprintf(1, "[%d] script %s returned error code %d\n", client, self->pathbuf, ret);
		respond(NULL, 0, 0);
		
	} else {
		len = getfilesize(self->pathbuf);
		if(len > sizeof(self->buffer))
			httpserver_turbomode(self, client);
		self->clients[client].responsestream = fopen(self->pathbuf, "r");
		respond(self->buffer, ulz_snprintf(self->buffer, sizeof(self->buffer), err200, httpserver_get_contenttype(self->pathbuf, fe), (int) len), 0);
	}
	
#undef respond

	writeheader:
	if(self->log) {
		if(rh == err500)
			ulz_fprintf(1, "[%d] 500.\n", client);
		else if(rh == err404)
			ulz_fprintf(1, "[%d] 404 %s\n", client, req->uri);
		else
			ulz_fprintf(1, "[%d] 200 %s\n", client, req->uri);
	}
	if(!(self->clients[client].responsestream_header = fopen(httpserver_get_client_responsestream_fn(self, client), rh ? "w+" : "r+"))) {
		ulz_fprintf(1, "%s\n", httpserver_get_client_responsestream_fn(self, client));
		log_perror("failed to open response file");
	}
	if(rh)
		if(fwrite(rh, 1, rl, self->clients[client].responsestream_header) != rl) {
			if(self->log)
				ulz_fprintf(1, "[%d] error writing to response file\n", client);
			_httpserver_disconnect_client(self, client, 1);
		}

	return res;
}

int httpserver_on_clientread (void* userdata, int fd, size_t nread) {
	httpserver* self = (httpserver*) userdata;
	clientrequest req;
	int ret;
	switch(self->clients[fd].status) {
		case CLIENT_CONNECTED:
			self->clients[fd].requeststream = fopen(httpserver_get_client_requeststream_fn(self, fd), "w+");
			if(!self->clients[fd].requeststream) {
				perror("failed to open requeststream");
				_httpserver_disconnect_client(self, fd, 1);
				return 2;
			}
			self->clients[fd].status = CLIENT_READING;
			self->clients[fd].requestsize = 0;
		case CLIENT_READING:
			if(!self->clients[fd].requestsize && nread == sizeof(self->buffer))
				httpserver_turbomode(self, fd);
			
			self->clients[fd].requestsize += nread;
			if(fwrite(self->buffer, 1, nread, self->clients[fd].requeststream) != nread) {
				if(self->log) 
					ulz_fprintf(1, "[%d] error writing to response file\n", fd);
				_httpserver_disconnect_client(self, fd, 1);
			}
			ret = httpserver_request_header_complete(self, fd, &req);
			if(!ret) return 0;
			if(ret == -1) {
				httpserver_deliver(self, fd, NULL);
				goto closehandle;
			}
			if(req.rqt == RQT_GET || self->clients[fd].requestsize == req.contentlength + req.streampos)
				httpserver_deliver(self, fd, &req);
			else
				return 0;
			if(self->clients[fd].responsestream_header) rewind(self->clients[fd].responsestream_header);
			closehandle:
			fclose(self->clients[fd].requeststream);
			self->clients[fd].requeststream = NULL;
			break;
		default:
			return 1;
	}
	//puts(self->buffer);
	return 0;
}

int httpserver_on_clientdisconnect (void* userdata, int fd) {
	httpserver* self = (httpserver*) userdata;
	if(fd < 0 || fd >= USER_MAX_FD) 
		return -1;
	return _httpserver_disconnect_client(self, fd, 0);
}

int httpserver_init(httpserver* srv, char* listenip, short port, const char* workdir, const char* servedir, int log, int timeout, int uid, int gid) {
	if(!srv || !workdir || !servedir) return 1;
	memset(srv, 0, sizeof(httpserver));
	srv->servedir.size = strlen(servedir);
	srv->servedir.ptr = (char*) servedir;
	srv->maxrequestsize = 20 * 1024 * 1024;
	srv->timeoutsec = timeout;
	srv->log = log;
	if(rocksockserver_init(&srv->serva, listenip, port, (void*) srv)) return -1;
	//dropping privs after bind()
	if(gid != -1 && setgid(gid) == -1)
		perror("setgid");
	if(gid != -1 && setgroups(0, NULL) == -1)
		perror("setgroups");
	if(uid != -1 && setuid(uid) == -1) 
		perror("setuid");

	// set up a temporary dir with 0700, and unpredictable name
	ulz_snprintf(srv->tempdir, sizeof(srv->tempdir), "%s/XXXXXX", workdir);
	if(!mkdtemp(srv->tempdir)) {
		perror("mkdtemp");
		exit(1);
	}
	
	srv->workdir.size = strlen(srv->tempdir);
	srv->workdir.ptr = srv->tempdir;
	
	if(rocksockserver_loop(&srv->serva, srv->buffer, sizeof(srv->buffer), &httpserver_on_clientconnect, &httpserver_on_clientread, &httpserver_on_clientwantsdata, &httpserver_on_clientdisconnect)) return -2;
	return 0;
}

__attribute__ ((noreturn))
void syntax(opts* opt) {
	ulz_printf("progname -srvroot=/srv/htdocs -tempfs=/dev/shm/ -listenip=0.0.0.0 -port=80 -timeout=30 -log=0 -uid=0 -gid=0\n");
	ulz_printf("all options except tempfs and srvroot are optional\n");
	ulz_printf("passed options were:\n");
	op_printall(opt);
	op_free(opt);
	exit(1);
}

int main(int argc, char** argv) {
	httpserver srv;
	static const char defaultip[] = "127.0.0.1";
	opts* opt = op_parse(argc, argv);
	stringptr* o_srvroot = op_get(opt, "srvroot");
	stringptr* o_tempfs = op_get(opt, "tempfs");
	stringptr* o_port = op_get(opt, "port");
	stringptr* o_listenip = op_get(opt, "listenip");
	stringptr* o_timeout = op_get(opt, "timeout");
	stringptr* o_log = op_get(opt, "log");
	stringptr* o_uid = op_get(opt, "uid");
	stringptr* o_gid = op_get(opt, "gid");
	
	int log = o_log ? atoi(o_log->ptr) : 1;
	int timeout = o_timeout ? atoi(o_timeout->ptr) : 30;
	char* ip = o_listenip ? o_listenip->ptr : (char*) defaultip;
	int port = o_port ? atoi(o_port->ptr) : 80;
	
	if(argc < 3 || !o_srvroot || !o_tempfs) syntax(opt);
	
	httpserver_init(&srv, ip, port, o_tempfs->ptr, o_srvroot->ptr, log, timeout, o_uid ? atoi(o_uid->ptr) : -1, o_gid ? atoi(o_gid->ptr) : -1);
	
	op_free(opt);
	return 0;
}

