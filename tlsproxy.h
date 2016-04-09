#ifndef __TLSPROXY_TLSPROXY_H
#define __TLSPROXY_TLSPROXY_H

#define FALSE 0
#define TRUE 1

extern char *connectaddr;
extern char *listenaddr;
extern char *keyfile;
extern char *certfile;
extern char *cacertfile;
extern char *hostname;
extern int debug;
extern int insecure;

#endif
