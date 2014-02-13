/* f-ftpbnc v1.6 */
/* $Rev: 421 $ $Date: 2008-01-30 22:56:40 +0100 (Wed, 30 Jan 2008) $ */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <sys/time.h>
#include <time.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <sys/select.h>

#include <signal.h>

extern char **environ;

#include "sha256.h"
#include "xtea-cipher.h"

#include "f-ftpbnc.h"

#define IDENTD_PORT 		113
#define TIMER_MULTIPLY		1000

#define TIMEOUT_IDENT		5 * TIMER_MULTIPLY
#define TIMEOUT_CONNECTING	30 * TIMER_MULTIPLY
#define TIMEOUT_CONNECTED	3*3600 * TIMER_MULTIPLY

/* #define DEBUG_SELECT */
/* #define DEBUG_DATA */
/* #define DEBUG_MEMBUFF */

/*** config loader/decrypter/decrambler ***/

/* config data only saved encrypted in program image */

#include "inc-config.h"

const struct CONFIG *config;

int config_load()
{
#if defined(SCRAMBLE_CONFIG)

    xtea_cbc_decipher(configdataencrypt, sizeof(configdataencrypt),
		      (unsigned long*)configkey, tea_iv);

    config = (struct CONFIG*)configdataencrypt;

#elif defined(ENCRYPT_CONFIG)

    char *inpass;
    unsigned char teakey[16];

    inpass = getpass("Password: ");
    if (!inpass) {
	printf("Could not read password.\n");
	return 0;
    }

    string_to_teakey(inpass, teakey);

    memset(inpass, 0, strlen(inpass)); /* scrub password */
         
    xtea_cbc_decipher(configdataencrypt, sizeof(configdataencrypt),
		      (unsigned long*)teakey, tea_iv);

    config = (struct CONFIG*)configdataencrypt;

#else
#error "No Configuration Available?"
#endif

    if (strncmp(config->signature, "f-ftpbnc", 9) == 0) return 1;

    printf("Configuration could not be read. Password is wrong?\n");

    return 0;
}

/*** debug output functions ***/

#define aprintf(args...)	_aprintf(__FILE__, __LINE__, args)
#define aprintferrno(args...)	_aprintferrno(__FILE__, __LINE__, args)

int aprintf_output = 0;

#define DBG_SYNCHECK(fmt,idx)	 __attribute__((format (printf, fmt, idx)))

void _aprintf(const char *file, int line, const char *format, ...) DBG_SYNCHECK(3,4);
void _aprintferrno(const char *file, int line, const char *format, ...) DBG_SYNCHECK(3,4);

inline void _aprintf(const char *file, int line, const char *format, ...)
{
    va_list ap;
    static char output[1024];
     
    if (!aprintf_output) return;

    va_start(ap, format);
    vsnprintf(output, sizeof(output), format, ap);
    va_end(ap);

    fprintf(stderr, "%s:%d> %s\n", file, line, output);
     
    return;
}

inline void _aprintferrno(const char *file, int line, const char *format, ...) {
    va_list ap;
    static char output[1024];

    if (!aprintf_output) return;
     
    va_start(ap, format);
    vsnprintf(output, sizeof(output), format, ap);
    va_end(ap);

    fprintf(stderr, "%s:%d> %s (errno %d : %s)\n", file, line, output, errno, strerror(errno));
     
    return;
}

/*** USR signal handler ***/

void signal_INT(int signum)
{
    /* reset handler for new signals */
    signal(signum, signal_INT);

    aprintf("Received SIGINT");

    exit(0);
}

void signal_USR1(int signum)
{
    /* reset handler for new signals */
    signal(signum, signal_USR1);

    aprintf("Received SIGUSR1");

    /* do nothing (esp not terminate) */
}

void signal_USR2(int signum)
{
    /* reset handler for new signals */
    signal(signum, signal_USR2);

    aprintf("Received SIGUSR2");

    /* do nothing (esp not terminate) */
}

void signal_PIPE(int signum)
{
    /* reset handler for new signals */
    signal(signum, signal_PIPE);

    aprintf("Received SIGPIPE");

    /* do nothing (esp not terminate) */
}

void signal_IO(int signum)
{
    /* reset handler for new signals */
    signal(signum, signal_IO);

    aprintf("Received SIGIO");

    /* do nothing (esp not terminate) */
}

void signal_SEGV(int signum)
{
#ifdef __linux__
    struct sigcontext_struct *sc;

    sc = (struct sigcontext_struct *)(&signum + 1);

    aprintf("Received SIGSEGV at address %lx", sc->eip);
#else
    signum++;
    aprintf("Received SIGSEGV");
#endif
    exit(1);
}                                         

/*** Network Functions ***/

int net_newsocket()
{
    struct protoent *pe;
    int tcpprotonum;
    int socketnum;
    int sockoptflag;

    pe = getprotobyname("tcp");
    tcpprotonum = pe ? pe->p_proto : 6;

    socketnum = socket(AF_INET, SOCK_STREAM, tcpprotonum);
    if (socketnum == -1) {
	aprintferrno("Cannot allocate new socket");
	return -1;
    }

    sockoptflag = 1;
    /* Enable sending of keep-alive messages on connection-oriented sockets. */
    if (setsockopt(socketnum, SOL_SOCKET, SO_KEEPALIVE, &sockoptflag, sizeof(sockoptflag)) != 0) {
	aprintferrno("Cannot set SO_KEEPALIVE on socket");
    }

    /* set SO_REUSEPORT */
#ifdef SO_REUSEPORT
    if (setsockopt(socketnum, SOL_SOCKET, SO_REUSEPORT, &sockoptflag, sizeof(sockoptflag)) != 0) {
	aprintferrno("Cannot set SO_REUSEPORT on socket");
    }
#else
    if (setsockopt(socketnum, SOL_SOCKET, SO_REUSEADDR, &sockoptflag, sizeof(sockoptflag)) != 0) {
	aprintferrno("Cannot set SO_REUSEADDR on socket");
    }
#endif

     /* maybe IP_TOS in future */

     /* TCP_NODELAY
	If set, disable the Nagle algorithm. This means that segments are always sent as soon 
	as possible, even if there is only a small amount of data.  When not set, data is 
	buffered until there is a sufficient amount to send out, thereby  avoiding the frequent
	sending of small packets, which results in poor utilization of the network. This option
	cannot be used at the same time as the option TCP_CORK. */
#ifdef SOL_TCP
    if (setsockopt(socketnum, SOL_TCP, TCP_NODELAY, &sockoptflag, sizeof(sockoptflag)) != 0) {
#else
    if (setsockopt(socketnum, 6, TCP_NODELAY, &sockoptflag, sizeof(sockoptflag)) != 0) {
#endif
	aprintferrno("Cannot set TCP_NODELAY on socket");
    }

    return socketnum;
}

unsigned long net_resolvehost(const char *host)
{
    struct in_addr ia;
    struct hostent *he;

    if (inet_aton(host, &ia)) {
	return ia.s_addr;
    }
     
    he = gethostbyname(host);
    if (he == NULL) {
	return 0;
    } else {
	return *(unsigned long *)he->h_addr;
    }
}

int net_bindsocket(int fd, const char *ip, unsigned short port)
{
    struct sockaddr_in	sa;

    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);

    if (ip != NULL) {
	if (strncmp(ip,"*", 2) == 0) {
	    sa.sin_addr.s_addr = htonl(INADDR_ANY);
	} else {
	    if (!(sa.sin_addr.s_addr = net_resolvehost(ip))) {
		aprintferrno("Cannot resolve host");
		return 0;
	    }
	}
    }
    else {
	sa.sin_addr.s_addr = htonl(INADDR_ANY);
    }

    if (bind(fd, (struct sockaddr *)&sa, sizeof(struct sockaddr)) != 0) {
	aprintferrno("Cannot bind socket");
	return 0;
    }

    return 1;
}

int net_connect(int fd, const char *ip, unsigned short port)
{
    struct sockaddr_in	sa;
    int r;

    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);

    if (!(sa.sin_addr.s_addr = net_resolvehost(ip))) {
	aprintferrno("Cannot resolve host");
	return 0;
    }

    r = connect(fd, (struct sockaddr *) &sa, sizeof (sa));
    if (r < 0 && errno == EINPROGRESS) {
	return 2;
    }
    if (r == 0) {
	return 1;
    }

    return 0;
}

const char *get_destinationip_cached()
{
    static int lastresolv = 0;
    static int cfgisip = 0;
    static struct hostent *he = NULL;

    int timenow = time(NULL);
    struct in_addr ia;
    struct hostent *he_new;

    if (cfgisip) return config->desthostname;

    if (lastresolv + config->destresolvetime <= timenow) {

	if (inet_aton(config->desthostname, &ia)) {
	    cfgisip = 1;
	    return config->desthostname;
	}

	aprintf("Resolving hostname %s", config->desthostname);
	he_new = gethostbyname(config->desthostname);
	if (he_new != NULL) {
	    he = he_new;
	}
	lastresolv = timenow;
    }     

    if (!he) return NULL;

    return inet_ntoa(*(struct in_addr *)he->h_addr);
}

/***
    memory buffering for non-blocking writes
***/

struct MEMBUFF {
    unsigned long	size, top, len;
    char*		data;
};

inline unsigned long membuff_available(struct MEMBUFF *m)
{
    return m->len;
}

inline void *membuff_top(struct MEMBUFF *m)
{
    return m->data + m->top;
}

inline void membuff_gobble(struct MEMBUFF *m, unsigned long len)
{
    m->top += len;
    m->len -= len;
}

inline void membuff_free(struct MEMBUFF *m)
{
    if (m->data) {
	free(m->data);
	m->data = NULL;
	m->size = m->len = m->top = 0;
    }
}

int membuff_write(struct MEMBUFF *m, const void *dest, size_t len)
{
#ifdef DEBUG_MEMBUFF
    aprintf("membuff_write(%p,%p,%d)", (void*)m, dest, len);
#endif
     
    if (len == 0) return 0;

    if (m->size >= len + m->top + m->len) {
	/* block still fits into buffer's tail */

	memcpy(m->data + m->top + m->len, dest, len);
	m->len += len;
	return len;
    }

    if (m->top > 0) {
	/* then we try to reorganize the buffer */

	memmove(m->data, m->data + m->top, m->len);
	m->top = 0;
    }    

    if (m->size >= len + m->len) {
	/* fits now? */

	memcpy(m->data + m->len, dest, len);
	m->len += len;
	return len;
    }

#ifdef DEBUG_MEMBUFF
    aprintf("membuff_write growing buffer to %lu", len + m->len);
#endif

    /* realloc a bigger buffer */
    m->data = (char*)realloc(m->data, len + m->len);
    m->size = len + m->len;

    memcpy(m->data + m->len, dest, len);
    m->len += len;
    return len;
}

/*** Hammer Protection Counting array ***/

struct HAMMER
{
    time_t            ltime;
    in_addr_t         lconn;
};

struct HAMMER *hammerlist = NULL;
int hammerlistlen = 0;

int hammer_check(struct sockaddr_in client)
{
    int n, freen, clientcount;
    time_t tnow = time(NULL);

    if (config->hammercount == 0) return 1;

    if (!hammerlist) {
	/* approximate a good hammer list length */
	hammerlistlen = config->hammercount * config->hammertime * 2;
	hammerlist = (struct HAMMER*)malloc(sizeof(struct HAMMER) * hammerlistlen);
	memset(hammerlist, 0, sizeof(struct HAMMER) * hammerlistlen);
	aprintf("Hammerlist allocated with %d entries", hammerlistlen);
    }

    clientcount = 0;
    freen = -1;

    for(n = 0; n < hammerlistlen; n++) {
	if (hammerlist[n].ltime >= (tnow - config->hammertime) &&
	    client.sin_addr.s_addr == hammerlist[n].lconn)
	{
	    clientcount++;
	}

	if (hammerlist[n].ltime == 0) {
	    if (freen < 0) freen = n;
	    break;
	}
	if (freen < 0 && hammerlist[n].ltime < (tnow - config->hammertime)) freen = n;
    }

    aprintf("Hammerlist found %d connects within last %d secs. Free entry %d will be filled.",
	    clientcount, config->hammertime, freen);

    if (clientcount >= config->hammercount) return 0;
 
    if (freen >= 0) {
	hammerlist[freen].ltime = tnow;
	hammerlist[freen].lconn = client.sin_addr.s_addr;
    }

    return 1;
}

/*** Proctitle stats setting (largly borrowed from proftpd) ***/

/* variables filled in as stats */
int clients = 0;
int socketsused = 0;

/* set from mkconfig */
#ifdef CHANGE_PROCTITLE

char **Argv = NULL;
char *LastArgv = NULL;

#if ( defined(__FreeBSD__) && __FreeBSD__ >= 4 ) || defined(__OpenBSD__)
#define HAVE_SETPROCTITLE
#endif

#ifdef __linux__
extern char *__progname, *__progname_full;
#endif

void proctitle_init(int argc, char *argv[], char *envp[])
{
    int i, envpsize;
    char **p;

    /* Move the environment so setproctitle can use the space. */
    for (i = envpsize = 0; envp[i] != NULL; i++)
	envpsize += strlen(envp[i]) + 1;

    if ((p = (char **)malloc((i + 1) * sizeof(char *))) != NULL) {
	environ = p;

	for (i = 0; envp[i] != NULL; i++)
	    if ((environ[i] = malloc(strlen(envp[i]) + 1)) != NULL)
		strcpy(environ[i], envp[i]);

	environ[i] = NULL;
    }

    Argv = argv;

    for (i = 0; i < argc; i++)
	if (!i || (LastArgv + 1 == argv[i]))
	    LastArgv = argv[i] + strlen(argv[i]);

    for (i = 0; envp[i] != NULL; i++)
	if ((LastArgv + 1) == envp[i])
	    LastArgv = envp[i] + strlen(envp[i]);

#ifdef __linux__
    /* Set the __progname and __progname_full variables so glibc and company
       don't go nuts. */
    __progname = strdup("f-ftpbnc");
    __progname_full = strdup(argv[0]);
#endif /* HAVE___PROGNAME */
}

void proctitle_set(const char *fmt, ...) {
     va_list msg;
     static char statbuf[BUFSIZ];

#ifndef HAVE_SETPROCTITLE
     char *p;
     int i, maxlen = (LastArgv - Argv[0]) - 2;
#endif /* HAVE_SETPROCTITLE */

     va_start(msg,fmt);

     memset(statbuf, 0, sizeof(statbuf));

#ifdef HAVE_SETPROCTITLE
     /* FreeBSD's setproctitle() automatically prepends the process name. */
     vsnprintf(statbuf, sizeof(statbuf), fmt, msg);
     setproctitle("%s", statbuf);

#else /* HAVE_SETPROCTITLE */

     vsnprintf(statbuf, sizeof(statbuf), fmt, msg);

#endif /* HAVE_SETPROCTITLE */

     va_end(msg);

#ifdef HAVE_SETPROCTITLE
     return;
#else
     i = strlen(statbuf);

     /* We can overwrite individual argv[] arguments.  Semi-nice. */
     snprintf(Argv[0], maxlen, "%s", statbuf);
     p = &Argv[0][i];

     while(p < LastArgv) *p++ = '\0';
     Argv[1] = NULL;

#endif /* HAVE_SETPROCTITLE */
}

void proctitle_update() {
    proctitle_set(config->proctitletext, clients, socketsused);
}

#else /* CHANGE_PROCTITLE (config variable) */

void proctitle_init(int argc, char *argv[], char *envp[]) {
    argc++;
    argv++;
    envp++;
}

void proctitle_update() {
}

#endif /* CHANGE_PROCTITLE (config variable) */

/*** Socket Status array ***/

struct SOCK;

typedef int (*socket_proc)(struct SOCK *status);

enum { STATUS_ERROR,
       STATUS_CLIENTIDENT, STATUS_CLIENTFORWARD,
       STATUS_SERVERCONNECT, STATUS_SERVERIDENT, STATUS_SERVERCONNECTED,
       STATUS_IDENTCONNECT, STATUS_IDENTCONNECTED };

struct SOCK
{
    int			used;

    int			status;
    int	    		client;

    int			fd;
    socket_proc		readhandler;
    socket_proc		writehandler;
    socket_proc		excepthandler;
    long		timeout;

    struct MEMBUFF	sendbuffer;
    struct MEMBUFF	preidentbuffer;

    char		*ident;

    struct SOCK*	forwardsock;
    struct SOCK*	identsock;

    struct sockaddr_in	sockaddr;

    int			oldfcntlflags;
};

int socketsnum = 0;
struct SOCK **sockets = NULL;

struct SOCK *socklist_findunused()
{
    int n, oldsocketsnum;
    for(n = 0; n < socketsnum; n++) {
	if (sockets[n]->used) continue;

	memset(sockets[n], 0, sizeof(struct SOCK));
	return sockets[n];
    }
     
    /* grow sockets list */
    oldsocketsnum = socketsnum;
    socketsnum += 10;
    sockets = (struct SOCK**)realloc(sockets, socketsnum * sizeof(struct SOCK*));

    for(n = oldsocketsnum; n < socketsnum; n++) {
	sockets[n] = malloc(sizeof(struct SOCK));
	memset(sockets[n], 0, sizeof(struct SOCK));
    }

    return sockets[oldsocketsnum];
}

/* Cleanup socket */

void socket_close(struct SOCK *ss)
{
    aprintf("Closing socket fd %d", ss->fd);

    if (close(ss->fd) != 0) {
	aprintferrno("Error closing socket");
    }

    membuff_free(&ss->sendbuffer);
    membuff_free(&ss->preidentbuffer);

    if (ss->ident) {
	free(ss->ident);
	ss->ident = NULL;
    }

    ss->used = 0;
    socketsused--;

    if (ss->client) {
	clients--;
	ss->client = 0;
	proctitle_update();
    }
}

/* The standard write socket handler. This flushes the membuffer for sends as
 * far as possible. Only writes are buffered in case the send queue of the tcp
 * conn fills up. */
int sockethandler_membuffsend(struct SOCK* ss)
{
    int w, wb;

    if (ss->status == STATUS_CLIENTIDENT) return 0;
    if (ss->status == STATUS_SERVERIDENT) return 0;

    while( ( wb = membuff_available(&ss->sendbuffer) ) > 0 )
    {
	aprintf("Flushing %d bytes from sendbuffer", wb);
	w = write(ss->fd, membuff_top(&ss->sendbuffer), wb);
	  
	if (w < 0) {
	    if (errno == EAGAIN) {
		return 0;
	    }
	    aprintferrno("Received error during sendbuffer flush on fd %d.", ss->fd);
	    socket_close(ss);
	    return 0;
	}

	membuff_gobble(&ss->sendbuffer, w);
    }
    return 0;
}

int needwrite_membuff(struct SOCK *ss)
{
    if (ss->status == STATUS_CLIENTIDENT) return 0;
    if (ss->status == STATUS_SERVERIDENT) return 0;

    return membuff_available(&ss->sendbuffer);
}

/* socket_write() will write out as much data as will go into the socket's
 * buffer. If no more data can be written the remaining part will be put into
 * the membuff. */
static int socket_write(struct SOCK *ss, const char *data, unsigned long datalen)
{
    int r;
    unsigned long rb = 0;

    if (membuff_available(&ss->sendbuffer)) {
	membuff_write(&ss->sendbuffer, data, datalen);
	return datalen;
    }

    while (rb < datalen)
    {
	r = write(ss->fd, data + rb, datalen - rb);

	if (r < 0) {
	    if (errno == EAGAIN) {
		membuff_write(&ss->sendbuffer,data + rb,datalen - rb);
		return datalen;
	    }

	    aprintferrno("Error during send on fd %d.", ss->fd);
	    return r;
	}

	rb += r;
    }

    return rb;
}

/* flush ident info and line buffer to server when its connected */

void socket_flushident(struct SOCK *ss)
{
    static char buff[512];
    struct SOCK *clt = ss->forwardsock;

    if (!clt) {
	aprintf("Stray server socket. Closing.");
	socket_close(ss);
	return;
    }     

    if (clt->ident) {
	snprintf(buff, sizeof(buff),
		 "IDNT %s@%s:%s\n",
		 clt->ident, inet_ntoa(clt->sockaddr.sin_addr), inet_ntoa(clt->sockaddr.sin_addr));

	if (socket_write(ss, buff, strlen(buff)) != (signed)strlen(buff)) {
	    aprintferrno("Short write");
	}
     
	aprintf("Sending %s", buff);

	free(clt->ident);
	clt->ident = NULL;
    }

    // flush pre-ident lines of client
    {
	int wb;
	while( ( wb = membuff_available(&ss->preidentbuffer) ) > 0 )
	{
	    aprintf("Flushing %d bytes from pre-ident buffer", wb);
	    int w = socket_write(ss, membuff_top(&ss->preidentbuffer), wb);
	  
	    if (w < 0) {
		aprintferrno("Received error during pre-ident buffer flush on fd %d.", ss->fd);
		socket_close(ss);
		return;
	    }

	    membuff_gobble(&ss->preidentbuffer, w);
	}
    }

    sockethandler_membuffsend(ss);

    clt->status = STATUS_CLIENTFORWARD;
    sockethandler_membuffsend(clt);
}

/*** Client/Server Data Relay function ***/

int sockethandler_relaydata(struct SOCK *ss)
{
    int inbytes, outbytes;
    static char inbuffer[4096];

    if (ss->status == STATUS_CLIENTFORWARD || ss->status == STATUS_CLIENTIDENT) {
	struct SOCK *fs = ss->forwardsock;
	  
	if (!fs) {
	    aprintf("Received data on socket with not forwardsock.");
	    socket_close(ss);
	    return 0;
	}

	if (fs->status == STATUS_SERVERCONNECT || fs->status == STATUS_SERVERIDENT) {
	    /* Queue data in linebuffer */

	    inbytes = read(ss->fd, inbuffer, sizeof inbuffer);

	    if (inbytes < 0) {
		aprintferrno("Error reading from client socket fd %d", ss->fd);
		socket_close(fs);
		socket_close(ss);
		return 0;
	    }
	    if (inbytes == 0) {
		aprintf("EOF received on client socket fd %d", ss->fd);
		socket_close(fs);
		socket_close(ss);
		return 0;
	    }

	    aprintf("Buffering %d bytes of pre-ident data from client socket %d.", inbytes, ss->fd);
	    membuff_write(&fs->preidentbuffer, inbuffer, inbytes);
	}
	else if (fs->status == STATUS_SERVERCONNECTED) {
	    /* write data onto forwarded socket */

	    inbytes = read(ss->fd, inbuffer, sizeof inbuffer);

	    if (inbytes < 0) {
		aprintferrno("Error reading from client socket fd %d", ss->fd);
		socket_close(fs);
		socket_close(ss);
		return 0;
	    }
	    if (inbytes == 0) {
		aprintf("EOF received on client socket fd %d", ss->fd);
		socket_close(fs);
		socket_close(ss);
		return 0;
	    }

	    ss->timeout = TIMEOUT_CONNECTED;

	    outbytes = socket_write(fs, inbuffer, inbytes);
	       
	    if (outbytes < 0) {
		aprintferrno("Error writing to server socket fd %d", ss->fd);
		socket_close(fs);
		socket_close(ss);
		return 0;
	    }

	    if (outbytes != inbytes) {
		aprintferrno("Short write.");
	    }

#ifdef DEBUG_DATA
	    aprintf("Forwarded %d bytes from client %d to server %d", inbytes, ss->fd, fs->fd);
#endif
	}
	else {
	    aprintf("Error in status for forwarded socket.");
	    socket_close(fs);
	    socket_close(ss);
	}
    }
    else if (ss->status == STATUS_SERVERCONNECTED) {
	struct SOCK *fs = ss->forwardsock;
	  
	if (!fs) {
	    aprintf("Received data on socket without forwardsock.");
	    socket_close(ss);
	    return 0;
	}

	/* write data onto forwarded socket */

	inbytes = read(ss->fd, inbuffer, sizeof inbuffer);

	if (inbytes < 0) {
	    aprintferrno("Error reading from server socket fd %d", ss->fd);
	    socket_close(fs);
	    socket_close(ss);
	    return 0;	       
	}
	if (inbytes == 0) {
	    aprintf("EOF received on server socket fd %d", ss->fd);
	    socket_close(fs);
	    socket_close(ss);
	    return 0;
	}

	ss->timeout = TIMEOUT_CONNECTED;

	outbytes = socket_write(fs, inbuffer, inbytes);

	if (outbytes < 0) {
	    aprintferrno("Error writing to socket");
	    socket_close(fs);
	    socket_close(ss);
	    return 0;
	}

	if (outbytes != inbytes) {
	    aprintferrno("Short write.");
	}

#ifdef DEBUG_DATA
	aprintf("Forwarded %d bytes from server %d to client %d", inbytes, ss->fd, fs->fd);
#endif
    }
    else {
	aprintf("Invalid status for socket fd %d: %d", ss->fd, ss->status);
    }

    return 0;
}

/* handle async connect to clients identd */

void sanitize_ident(char *i)
{
    while(*i) {
	if (*i == '@') *i = '.';
	if (*i == '*') *i = '.';
	if (*i == '[') *i = '.';
	if (*i == ']') *i = '.';
	if (*i == '{') *i = '.';
	if (*i == '}') *i = '.';	  
	i++;
    }
}

int sockethandler_ident_read(struct SOCK *ss)
{
    int inbytes, r;
    static char inbuffer[4096], ident[256];
    int remote_port, local_port;
	 
    struct SOCK *cltss = ss->forwardsock; 
    struct SOCK *srvss;

    if (!cltss) {
	aprintf("Stray ident socket. Closing.");
	socket_close(ss);
	return 0;
    }

    srvss = cltss->forwardsock;
    if (!srvss) {
	aprintf("Stray ident socket. Closing.");
	socket_close(cltss);
	socket_close(ss);
	return 0;
    }

    /* read data from ident socket */

    inbytes = read(ss->fd, inbuffer, sizeof inbuffer);
     
    if (inbytes < 0) {
	aprintferrno("Error reading from ident socket");
	socket_close(ss);

	cltss->ident = strdup("*");

	if (srvss->status == STATUS_SERVERIDENT) {
	    socket_flushident(srvss);

	    srvss->status = STATUS_SERVERCONNECTED;
	    srvss->readhandler = sockethandler_relaydata;
	    srvss->timeout = TIMEOUT_CONNECTED;

	    cltss->timeout = TIMEOUT_CONNECTED;
	}
	return 0;
    }
    if (inbytes == 0) {
	aprintf("EOF received on ident socket fd %d", ss->fd);
	socket_close(ss);

	cltss->ident = strdup("*");

	if (srvss->status == STATUS_SERVERIDENT) {
	    socket_flushident(srvss);

	    srvss->status = STATUS_SERVERCONNECTED;
	    srvss->readhandler = sockethandler_relaydata;
	    srvss->timeout = TIMEOUT_CONNECTED;

	    cltss->timeout = TIMEOUT_CONNECTED;
	}
	return 0;
    }

    inbuffer[inbytes] = 0;
    r = sscanf(inbuffer, "%d , %d : USERID :%*[^:]:%255s", &remote_port, &local_port, ident);

    /* check ident responce */
    if (r != 3 || remote_port != ntohs(cltss->sockaddr.sin_port) || local_port != config->localport) {

	r = sscanf(inbuffer, "%d , %d : ERROR :", &remote_port, &local_port);

	if (r != 2 || remote_port != ntohs(cltss->sockaddr.sin_port) || local_port != config->localport) {
	    aprintf("Bogus ident reply: %s\n",inbuffer);
	    socket_close(ss);

	    cltss->ident = strdup("*");

	    if (srvss->status == STATUS_SERVERIDENT) {
		socket_flushident(srvss);

		srvss->status = STATUS_SERVERCONNECTED;
		srvss->readhandler = sockethandler_relaydata;
		srvss->timeout = TIMEOUT_CONNECTED;

		cltss->timeout = TIMEOUT_CONNECTED;
	    }
	    return 0;
	}
	strcpy(ident, "*");
    }

    aprintf("Received ident %s", ident);
    socket_close(ss);

    cltss->ident = strdup(ident);
    sanitize_ident(cltss->ident);

    cltss->timeout = TIMEOUT_CONNECTED;

    if (srvss->status == STATUS_SERVERIDENT) {
	socket_flushident(srvss);
     
	srvss->status = STATUS_SERVERCONNECTED;
	srvss->readhandler = sockethandler_relaydata;
	srvss->timeout = TIMEOUT_CONNECTED;
    }
    return 0;
}

int sockethandler_ident_connect(struct SOCK *ss)
{
    int error, r;
    unsigned int len = sizeof(error);
    static char buff1[256];

    struct SOCK *cltss = ss->forwardsock;
    struct SOCK *srvss;

    if (!cltss) {
	aprintf("Stray ident socket. Closing.");
	socket_close(ss);
	return 0;
    }

    srvss = cltss->forwardsock;
    if (!srvss) {
	aprintf("Stray ident socket. Closing.");
	socket_close(cltss);
	socket_close(ss);
	return 0;
    }

    len = sizeof(error);
    if (getsockopt(ss->fd, SOL_SOCKET, SO_ERROR, &error, &len) < 0) {
	aprintf("Could not get errno from async ident socket.");
	socket_close(ss);

	cltss->ident = strdup("*");

	if (srvss->status == STATUS_SERVERIDENT) {
	    socket_flushident(srvss);

	    srvss->status = STATUS_SERVERCONNECTED;
	    srvss->readhandler = sockethandler_relaydata;
	    srvss->timeout = TIMEOUT_CONNECTED;

	    cltss->timeout = TIMEOUT_CONNECTED;
	}
	return 0;
    }

    if (error != 0) {
	aprintf("fd %d could not connect to ident port: %s", ss->fd, strerror(error));
	socket_close(ss);

	cltss->ident = strdup("*");

	if (srvss->status == STATUS_SERVERIDENT) {
	    socket_flushident(srvss);

	    srvss->status = STATUS_SERVERCONNECTED;
	    srvss->readhandler = sockethandler_relaydata;
	    srvss->timeout = TIMEOUT_CONNECTED;

	    cltss->timeout = TIMEOUT_CONNECTED;
	}
	return 0;
    }

    if (fcntl(ss->fd, F_SETFL, ss->oldfcntlflags) != 0) {
	aprintferrno("Cannot set ident connection socket back to blocking");
    }

    ss->writehandler = NULL;
    ss->readhandler = sockethandler_ident_read;
    aprintf("Ident Connection established. Requesting ident for %d,%d",
	    ntohs(cltss->sockaddr.sin_port), config->localport);

    snprintf(buff1, sizeof(buff1),
	     "%d,%d\r\n", ntohs(cltss->sockaddr.sin_port), config->localport);

    r = socket_write(ss, buff1, strlen(buff1));
    if (r < 0) {
	aprintferrno("Error writing to ident socket.\n");
	socket_close(ss);

	cltss->ident = strdup("*");

	if (srvss->status == STATUS_SERVERIDENT) {
	    socket_flushident(srvss);

	    srvss->status = STATUS_SERVERCONNECTED;
	    srvss->readhandler = sockethandler_relaydata;
	    srvss->timeout = TIMEOUT_CONNECTED;

	    cltss->timeout = TIMEOUT_CONNECTED;
	}
    }
     
    return 0;
}

int sockethandler_ident_timeout(struct SOCK *ss)
{
    struct SOCK *cltss = ss->forwardsock;
    struct SOCK *srvss;

    if (!cltss) {
	aprintf("Stray ident socket. Closing.");
	socket_close(ss);
	return 0;
    }

    srvss = cltss->forwardsock;
    if (!srvss) {
	aprintf("Stray ident socket. Closing.");
	socket_close(cltss);
	socket_close(ss);
	return 0;
    }

    aprintferrno("Timeout while connecting to ident port.");
    socket_close(ss);

    cltss->timeout = TIMEOUT_CONNECTED;
    cltss->ident = strdup("*");

    if (srvss->status == STATUS_SERVERIDENT) {
	socket_flushident(srvss);
     
	srvss->status = STATUS_SERVERCONNECTED;
	srvss->readhandler = sockethandler_relaydata;

	srvss->timeout = TIMEOUT_CONNECTED;
    }

    return 0;
}

/* incoming data from server in pre-relaydata status */

int sockethandler_server_preident(struct SOCK *ss)
{
    int inbytes;
    static char inbuffer[4096];

    struct SOCK *fs = ss->forwardsock;
     
    if (!fs) {
	aprintf("Received serverdata for closed forwardsock.");
	socket_close(ss);
	return 0;
    }

    if (ss->status == STATUS_SERVERIDENT) {
	  
	/* read data from server socket */

	inbytes = read(ss->fd, inbuffer, sizeof(inbuffer));

	if (inbytes < 0) {
	    aprintferrno("Error reading from socket fd %d", ss->fd);
	    socket_close(fs);
	    socket_close(ss);
	    return 0;
	}
	if (inbytes == 0) {
	    /* socket is closed */

	    aprintf("EOF received on fd %d", ss->fd);
	    socket_close(fs);
	    socket_close(ss);
	    return 0;
	}

	aprintf("Buffering %d bytes of data from server.", inbytes);
	membuff_write(&fs->sendbuffer, inbuffer, inbytes);
    }
    else {
	aprintf("Invalid status for socket %d: %d", ss->fd, ss->status);
    }

    return 0;
}

/* once the server connection is established this proc gets called */

int sockethandler_server_connect(struct SOCK *ss)
{
    int error;
    unsigned int len = sizeof(error);

    struct SOCK *fs = ss->forwardsock;

    if (getsockopt(ss->fd, SOL_SOCKET, SO_ERROR, &error, &len) < 0) {
	aprintf("Could not get errno from async ident socket.");
	if (fs) socket_close(fs);
	socket_close(ss);
	return 0;
    }

    if (error == 0) {

	ss->writehandler = NULL;
	ss->readhandler = sockethandler_server_preident;
	ss->timeout = TIMEOUT_CONNECTING;
	aprintf("Connection established. fd is %d", ss->fd);

	ss->status = STATUS_SERVERIDENT;

	if (!fs) {
	    aprintf("Error. connection to server without a client connection.\n");
	    socket_close(ss);
	    return 0	;
	}

	if (fs->ident) {
	    /* identing was faster than server connection */

	    socket_flushident(ss);

	    ss->status = STATUS_SERVERCONNECTED;
	    ss->readhandler = sockethandler_relaydata;
	    ss->timeout = TIMEOUT_CONNECTED;
	}

	if (!config->ident) {
	    sockethandler_membuffsend(ss);

	    ss->status = STATUS_SERVERCONNECTED;
	    ss->readhandler = sockethandler_relaydata;
	    ss->timeout = TIMEOUT_CONNECTED;
	}

	return 0;
    }
    else {
	errno = error;
	aprintferrno("Error connection to server");
	if (fs->identsock) socket_close(fs->identsock);
	if (fs) socket_close(fs);
	socket_close(ss);
	return 0;
    }
}

int sockethandler_client_hammerclose(struct SOCK *ss)
{
    const char *hammertext = "421 Hammer Protection: Connection quota exceeded!\n";

    write(ss->fd, hammertext, strlen(hammertext));
     
    socket_close(ss);
    return 0;  
}

/* Client accept handler:
   accepts a new connection through the listensocket,
   initials an async connect to the server. */

int sockethandler_acceptclient(struct SOCK *ss)
{
    int newsocket;
    struct sockaddr_in	csa;
    socklen_t csa_len = sizeof(csa);
    struct SOCK *newcs;
    int oldopts;

    aprintf("Accept on fd %d", ss->fd);
    newsocket = accept(ss->fd, (struct sockaddr*)&csa, &csa_len);

    aprintf("Accepted connection from %s port %d. new fd is %d", inet_ntoa(csa.sin_addr), ntohs(csa.sin_port), newsocket);

    newcs = socklist_findunused();
    newcs->used = 1;
    socketsused++;
    clients++;
    newcs->client = 1;
    newcs->fd = newsocket;
    newcs->readhandler = sockethandler_relaydata;
    newcs->status = STATUS_CLIENTIDENT;
    newcs->timeout = TIMEOUT_CONNECTING;
    newcs->sockaddr = csa;

    if (!hammer_check(csa)) {
	aprintf("Hammer Protection: Connection quota exceeded. Dropping new connection.");

	newcs->readhandler = NULL;
	newcs->writehandler = sockethandler_client_hammerclose;
	return 0;
    }

    proctitle_update();

    /* set client socket to non-blocking */
    oldopts = fcntl(newsocket, F_GETFL);
    if (fcntl(newsocket, F_SETFL, oldopts | O_NONBLOCK) != 0) {
	aprintferrno("Cannot set client connection socket to non-blocking");
    }

    /* open non-blocking connection to main host */
    {
	int servsock, r;
	struct SOCK *srvss;
	const char *destip;

	servsock = net_newsocket();
	if (!net_bindsocket(servsock, config->destbindip, 0)) {
	    aprintferrno("Cannot bind to destination bindip %s", config->destbindip);
	    socket_close(newcs);
	    close(servsock);
	    return 0;
	}

	/* set socket to non-blocking */
	oldopts = fcntl(servsock, F_GETFL);
	if (fcntl(servsock, F_SETFL, oldopts | O_NONBLOCK) != 0) {
	    aprintferrno("Cannot set server connection socket to non-blocking");
	}
	  
	destip = get_destinationip_cached();
	if (!destip) {
	    aprintferrno("Cannot resolve destination hostname");
	    socket_close(newcs);
	    close(servsock);
	    return 0;
	}
	r = net_connect(servsock, destip, config->destport);
	aprintf("Connecting fd %d to server at %s:%d", servsock, config->desthostname, config->destport);

	srvss = socklist_findunused();
	srvss->used = 1;
	socketsused++;
	srvss->fd = servsock;
	srvss->oldfcntlflags = oldopts;
	newcs->timeout = TIMEOUT_CONNECTING;
	if (r == 2) {
	    srvss->writehandler = sockethandler_server_connect;
	    srvss->status = STATUS_SERVERCONNECT;
	}
	else if (r == 1) {
	    srvss->readhandler = sockethandler_relaydata;
	    srvss->status = STATUS_SERVERCONNECTED;
	}

	srvss->forwardsock = newcs;
	newcs->forwardsock = srvss;
    }

    /* open an ident connection to incoming client */
    if (config->ident)
    {
	int identsock, r;
	struct SOCK *idtss;

	identsock = net_newsocket();
	if (!net_bindsocket(identsock, config->localip, 0)) {
	    aprintferrno("Cannot bind to localip %s", config->localip);
	    socket_close(newcs->forwardsock);
	    socket_close(newcs);
	    return 0;
	}

	/* set socket to non-blocking */
	oldopts = fcntl(identsock, F_GETFL);
	if (fcntl(identsock, F_SETFL, oldopts | O_NONBLOCK) != 0) {
	    aprintferrno("Cannot set ident connection socket to non-blocking");
	}

	aprintf("Connecting fd %d to client ident %s:%d",
		identsock, inet_ntoa(newcs->sockaddr.sin_addr), IDENTD_PORT);

	r = net_connect(identsock, inet_ntoa(newcs->sockaddr.sin_addr), IDENTD_PORT);

	idtss = socklist_findunused();
	idtss->used = 1;
	socketsused++;
	idtss->fd = identsock;
	idtss->oldfcntlflags = oldopts;
	idtss->timeout = TIMEOUT_IDENT;
	if (r == 2) {
	    idtss->writehandler = sockethandler_ident_connect;
	    idtss->excepthandler = sockethandler_ident_timeout;
	    idtss->status = STATUS_IDENTCONNECT;
	}
	else if (r == 1) {
	    idtss->readhandler = sockethandler_ident_connect;
	    idtss->status = STATUS_IDENTCONNECTED;
	}

	idtss->forwardsock = newcs;
	newcs->identsock = idtss;
    }
    else /* no ident requesting */
    {
	newcs->status = STATUS_CLIENTFORWARD;
	newcs->timeout = TIMEOUT_CONNECTED;
    }
     
    return 0;
}

/*** timeval calculation function ***/

int timeval_subtract(struct timeval *result, struct timeval *x, struct timeval *y)
{
    /* Perform the carry for the later subtraction by updating y. */
    if (x->tv_usec < y->tv_usec) {
	int nsec = (y->tv_usec - x->tv_usec) / 1000000 + 1;
	y->tv_usec -= 1000000 * nsec;
	y->tv_sec += nsec;
    }
    if (x->tv_usec - y->tv_usec > 1000000) {
	int nsec = (y->tv_usec - x->tv_usec) / 1000000;
	y->tv_usec += 1000000 * nsec;
	y->tv_sec -= nsec;
    }
     
    /* Compute the time remaining to wait.
       tv_usec  is certainly positive. */
    result->tv_sec = x->tv_sec - y->tv_sec;
    result->tv_usec = x->tv_usec - y->tv_usec;
	
    /* Return 1 if result is negative. */
    return x->tv_sec < y->tv_sec;
}

/*** main select()-based dispatch loop ***/

void main_selectloop()
{
    int n, maxfd, mintimeout, r, found;
    fd_set read_selectset;
    fd_set write_selectset;
    fd_set except_selectset;
    struct timeval timer, timer2, timerdelta, selecttimeout;
    int timeouteslaped;
  
    gettimeofday(&timer, NULL);

    while(1) {

	maxfd = 0;
	mintimeout = 10 * TIMER_MULTIPLY;
	FD_ZERO(&read_selectset);
	FD_ZERO(&write_selectset);
	FD_ZERO(&except_selectset);

	for(n = 0; n < socketsnum; n++) {
	    if (!sockets[n]) continue;
	    if (!sockets[n]->used) continue;

	    if (sockets[n]->readhandler)
		FD_SET(sockets[n]->fd, &read_selectset);

	    /* if its the membuffer write handler, check membuffer fill level */
	    if (sockets[n]->writehandler == NULL && needwrite_membuff(sockets[n])) {
		FD_SET(sockets[n]->fd, &write_selectset);
	    }
	    else if (sockets[n]->writehandler) {
		FD_SET(sockets[n]->fd, &write_selectset);
	    }

	    /* catch exceptions for all sockets */
	    FD_SET(sockets[n]->fd, &except_selectset);

	    if (sockets[n]->fd + 1 > maxfd) maxfd = sockets[n]->fd + 1;

	    if (sockets[n]->timeout > 0 && mintimeout > sockets[n]->timeout)
		mintimeout = sockets[n]->timeout;
	}

	selecttimeout.tv_sec = mintimeout / TIMER_MULTIPLY;
	selecttimeout.tv_usec = (mintimeout % TIMER_MULTIPLY) * 1000000 / TIMER_MULTIPLY;

#ifdef DEBUG_SELECT
	aprintf("selecting. timeout = %d", mintimeout);
#endif
	r = select(maxfd, &read_selectset, &write_selectset, &except_selectset, &selecttimeout);

	/* Calculate time spent in select and reduce timeouts,
	   while checking for timeout underruns */
	       
	gettimeofday(&timer2, NULL);
	timeval_subtract(&timerdelta, &timer2, &timer);
	       
	timeouteslaped = (timerdelta.tv_sec * TIMER_MULTIPLY) + (timerdelta.tv_usec * TIMER_MULTIPLY / 1000000 + 1);
#ifdef DEBUG_SELECT
	aprintf("Time %dtsec eslaped while in select.", timeouteslaped);
#endif

	for(n = 0; n < socketsnum; n++) {
	    if (!sockets[n]) continue;
	    if (!sockets[n]->used) continue;
	    if (sockets[n]->timeout == 0) continue;

	    if (sockets[n]->timeout <= timeouteslaped) {
		/* socket timeouted */
		aprintf("Timeout on socket fd %d", sockets[n]->fd);
		sockets[n]->timeout = 0;
			 
		if (sockets[n]->excepthandler) {
		    sockets[n]->excepthandler(sockets[n]);
		}
		else { /* default on exception is to close the socket */
		    socket_close(sockets[n]);
		}
	    }
	    else {
#ifdef DEBUG_SELECT
		aprintf("Decreased timeout value of %d fd %d from %lu to %lu",
			n, sockets[n]->fd, sockets[n]->timeout, sockets[n]->timeout - timeouteslaped);
#endif

		sockets[n]->timeout -= timeouteslaped;
	    }
	}
	       
	timer = timer2;

	/* figure out which socket got an event */

	if (r < 0) {
	    aprintferrno("select failed");
	}
	else if (r == 0) {
	    aprintf("select timeout.");
	}
	else {
	    for(n = 0; n < socketsnum && r > 0; n++) {
		if (!sockets[n]) continue;
		if (!sockets[n]->used) continue;

		found = 0;

		if (FD_ISSET(sockets[n]->fd, &read_selectset) && sockets[n]->readhandler) {
		    sockets[n]->readhandler(sockets[n]);
		    found = 1;
		}
		if (FD_ISSET(sockets[n]->fd, &write_selectset)) {
		    if (sockets[n]->writehandler) {
			sockets[n]->writehandler(sockets[n]);
		    }
		    else {
			sockethandler_membuffsend(sockets[n]);
		    }
		    found = 1;
		}
		if (FD_ISSET(sockets[n]->fd, &except_selectset)) {
		    found = 1;
		    aprintf("Exception on socket %d",sockets[n]->fd);
		    if (sockets[n]->excepthandler) {
			sockets[n]->excepthandler(sockets[n]);
		    }
		    else { /* default on exception is to close the socket */
			socket_close(sockets[n]);
		    }
		}

		if (found) r--;
	    }
	}
    }
}

/*** pid file functions ***/

int main_checkpidfile(const char *pidfile)
{
    FILE *pf;
    int cpid;
    char procpidpath[256];
    char exepath[512];

    if (!pidfile || !*pidfile) return 0;

    pf = fopen(pidfile, "r");
    if (pf == NULL) {
	printf("Cannot read pidfile %s: %s", pidfile, strerror(errno));
	return 0;
    }

    if (fscanf(pf, "%d", &cpid) != 1) {
	fclose(pf);
	return 0;
    }

    fclose(pf);
     
    snprintf(procpidpath, 256, "/proc/%d/exe", cpid);

    if (readlink(procpidpath, exepath, sizeof(exepath)) <= 0) {
	return 0;
    }

    return 1;
}

void main_writepidfile(const char *pidfile, pid_t pid)
{
    FILE *pf;

    if (!pidfile || !*pidfile) return;

    pf = fopen(pidfile, "w");
    if (pf == NULL) {
	aprintf("Cannot create pidfile %s: %s", pidfile, strerror(errno));
	return;
    }
    fprintf(pf, "%d", pid);
    fclose(pf);
}

/*** main program bootstrapper ***/

int main (int argc, char *argv[])
{
    int n, mypid;
    int dofork = 1;
    const char *pidfile = NULL;

    aprintf_output = 0;

    if (argc > 1) {
	n = 1;
	while(n < argc) {
	    if (strcmp(argv[n],"-h") == 0) {
		printf("Usage: %s <options>\n",argv[0]);
		printf("Options: -n = dont demonize\n");
		printf("         -d = output debug msgs and dont demonize\n");
		printf("         -pidfile <file> = check and write pid number to file\n");
		return 0;
	    }
	    else if (strcmp(argv[n],"-d") == 0) {
		dofork = 0;
		aprintf_output = 1;
	    }
	    else if (strcmp(argv[n],"-n") == 0) {
		dofork = 0;
	    }
	    else if (strcmp(argv[n],"-pidfile") == 0 && n+1 < argc) {
		n++;
		pidfile = argv[n];
	    }
	    else {
		printf("Unknown parameter %s\n", argv[n]);
		return 0;
	    }
	    n++;
	}
    }    

    if (pidfile) {
	if (main_checkpidfile(pidfile)) {
	    /* already running fine */
	    return 0;
	}
    }

    if (!config_load()) return 1;

    proctitle_init(argc,argv,environ);

    printf("%s starting: config %s\n", argv[0], config->configname);

    signal(SIGINT, signal_INT);
    signal(SIGUSR1, signal_USR1);
    signal(SIGUSR2, signal_USR2);
    signal(SIGPIPE, signal_PIPE);
    signal(SIGIO, signal_IO);
    signal(SIGSEGV, signal_SEGV);

    {
	int listensocket;

	if ( (listensocket = net_newsocket()) < 0) {
	    return 1;
	}

	if (!net_bindsocket(listensocket, config->localip, config->localport)) {
	    printf("Cannot bind socket to %s:%d, %s\n", config->localip, config->localport, strerror(errno));
	    return 1;
	}

	/* go into listening mode */
	if (listen(listensocket, SOMAXCONN) != 0) {
	    printf("Cannot listen on %s:%d, %s\n", config->localip, config->localport, strerror(errno));
	    return 1;
	}

	aprintf("Now listening on %s:%d", config->localip, config->localport);

	/* insert listener socket */
	{
	    struct SOCK *ss = socklist_findunused();
	    ss->used = 1;
	    socketsused++;
	    ss->fd = listensocket;
	    ss->readhandler = sockethandler_acceptclient;
	}
    }

    if (dofork) {
	mypid = fork();
	if (mypid < 0) {
	    printf("First fork into background failed.\n");
	    return 0;
	}
	if (mypid > 0) {
	    return 0;
	}
	/* else drop through */

	/* Become a process/session group leader. */
	setsid();
	mypid = fork();
	if (mypid != 0) {
	    if (mypid < 0) {
		printf("Second fork into background failed.\n");
	    }
	    return 0;
	}

	printf("%s forked into background as pid %d.\n", argv[0], getpid());
    }

    if (pidfile) {
	main_writepidfile(pidfile, getpid());
    }

    if (dofork) {
	/* Avoid keeping any directory in use. */
	chdir("/");

	close(0);
	close(1);
	close(2);
    }

    main_selectloop();

    aprintf("This should never be reached.");

    return 0;
}
