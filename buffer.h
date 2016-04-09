#ifndef __TLSPROXY_BUFFERS_H
#define __TLSPROXY_BUFFERS_H

#include <stdlib.h>
#include <sys/types.h>

typedef struct buffer buffer_t;

buffer_t *bufNew (ssize_t size, ssize_t hwm);
void bufFree (buffer_t * b);
ssize_t bufGetReadSpan (buffer_t * b, void **addr);
ssize_t bufGetWriteSpan (buffer_t * b, void **addr);
void bufDoneRead (buffer_t * b, ssize_t size);
void bufDoneWrite (buffer_t * b, ssize_t size);
int bufIsEmpty (buffer_t * b);
int bufIsFull (buffer_t * b);
int bufIsOverHWM (buffer_t * b);
ssize_t bufGetFree (buffer_t * b);
ssize_t bufGetCount (buffer_t * b);

#endif
