#ifndef __TLSPROXY_CRYPTO_H
#define __TLSPROXY_CRYPTO_H

int crypto_init ();

typedef struct tlssession tlssession_t;
tlssession_t *newtlssession (int isserver, char *hostname);
void closetlssession (tlssession_t * s);
int mainloop (int cryptfd, int plainfd, tlssession_t * session);
void handlesignal (int signal);

#endif
