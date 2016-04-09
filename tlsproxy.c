#define _GNU_SOURCE
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>

#include "tlsproxy.h"
#include "crypto.h"

char *connectaddr = NULL;
char *listenaddr = NULL;
char *keyfile = NULL;
char *certfile = NULL;
char *cacertfile = NULL;
char *hostname = NULL;
int debug = 0;
int insecure = 0;

char *defaultport = "12345";

int
bindtoaddress (char *addrport)
{
  struct addrinfo hints;
  struct addrinfo *result, *rp;
  int fd, s;

  memset (&hints, 0, sizeof (struct addrinfo));
  hints.ai_flags = AI_PASSIVE;	/* For wildcard IP address */
  hints.ai_family = AF_UNSPEC;	/* Allow IPv4 or IPv6 */
  hints.ai_socktype = SOCK_STREAM;	/* Stream socket */
  hints.ai_protocol = 0;	/* any protocol */

  char *addr = strdupa (addrport);
  char *colon = strrchr (addr, ':');
  char *port = defaultport;
  if (colon)
    {
      *colon = 0;
      port = colon + 1;
    }

  s = getaddrinfo (addr, port, &hints, &result);
  if (s != 0)
    {
      fprintf (stderr, "Error in address %s: %s\n", addr, gai_strerror (s));
      return -1;
    }

  /* attempt to bind to each address */

  for (rp = result; rp != NULL; rp = rp->ai_next)
    {
      fd = socket (rp->ai_family, rp->ai_socktype, rp->ai_protocol);

      if (fd >= 0)
	{
	  int one = 1;
	  if (setsockopt (fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof (one)) <
	      0)
	    {
	      close (fd);
	      continue;
	    }
	  if (bind (fd, rp->ai_addr, rp->ai_addrlen) == 0)
	    break;
	  close (fd);
	}
    }

  if (!rp)
    {
      fprintf (stderr, "Error binding to %s:%s: %m\n", addr, port);
      return -1;
    }

  freeaddrinfo (result);	/* No longer needed */

  if (listen (fd, 5) < 0)
    {
      close (fd);
      return -1;
    }

  return fd;
}

int
connecttoaddress (char *addrport)
{
  struct addrinfo hints;
  struct addrinfo *result, *rp;
  int fd, s;

  memset (&hints, 0, sizeof (struct addrinfo));
  hints.ai_flags = AI_PASSIVE;	/* For wildcard IP address */
  hints.ai_family = AF_UNSPEC;	/* Allow IPv4 or IPv6 */
  hints.ai_socktype = SOCK_STREAM;	/* Stream socket */
  hints.ai_protocol = 0;	/* any protocol */

  char *addr = strdupa (addrport);
  char *colon = strrchr (addr, ':');
  char *port = defaultport;
  if (colon)
    {
      *colon = 0;
      port = colon + 1;
    }

  if (!hostname)
    hostname = strdup (addr);

  s = getaddrinfo (addr, port, &hints, &result);
  if (s != 0)
    {
      fprintf (stderr, "Error in address %s: %s\n", addr, gai_strerror (s));
      return -1;
    }

  /* attempt to connect to each address */
  for (rp = result; rp != NULL; rp = rp->ai_next)
    {
      fd = socket (rp->ai_family, rp->ai_socktype, rp->ai_protocol);
      if (fd >= 0)
	{
	  if (connect (fd, rp->ai_addr, rp->ai_addrlen) == 0)
	    break;
	  close (fd);
	}
    }

  if (!rp)
    {
      fprintf (stderr, "Error connecting to %s:%s: %m\n", addr, port);
      return -1;
    }

  freeaddrinfo (result);	/* No longer needed */

  return fd;
}


int
runproxy (int plainfd)
{
  int cryptfd;
  if ((cryptfd = connecttoaddress (connectaddr)) < 0)
    {
      fprintf (stderr, "Could not connect crypt listener\n");
      close (plainfd);
      return -1;
    }

  tlssession_t *session = newtlssession (FALSE, hostname);
  if (!session)
    {
      fprintf (stderr, "Could create TLS session\n");
      close (cryptfd);
      close (plainfd);
      return -1;
    }

  int ret = mainloop (cryptfd, plainfd, session);

  closetlssession (session);
  close (cryptfd);
  close (plainfd);

  if (ret < 0)
    {
      fprintf (stderr, "TLS proxy exited with an error\n");
      return -1;
    }
  return 0;
}


int
runlistener ()
{
  int listenfd;
  if ((listenfd = bindtoaddress (listenaddr)) < 0)
    {
      fprintf (stderr, "Could not bind plaintext listener\n");
      return -1;
    }

  int fd;
  if ((fd = accept (listenfd, NULL, NULL)) < 0)
    {
      fprintf (stderr, "Accept failed\n");
      return -1;
    }
  return runproxy (fd);
}


void
usage ()
{
  fprintf (stderr, "tlsproxy\n\n\
Usage:\n\
     tlsproxy [OPTIONS]\n\
\n\
Options:\n\
     -c, --connect ADDRRESS    Connect to ADDRESS\n\
     -l, --listen ADDRESS      Listen on ADDRESS\n\
     -K, --key FILE            Use FILE as private key\n\
     -C, --cert FILE           Use FILE as public key\n\
     -A, --cacert FILE         Use FILE as public CA cert file\n\
     -H, --hostname HOSTNAME   Use HOSTNAME to validate the CN of the peer\n\
     -i, --insecure            Do not validated certificates\n\
     -d, --debug               Turn on debugging\n\
     -h, --help                Show this usage message\n\
\n\
\n");
}

void
processoptions (int argc, char **argv)
{
  while (1)
    {
      static struct option longopts[] = {
	{"connect", required_argument, 0, 'c'},
	{"listen", required_argument, 0, 'l'},
	{"key", optional_argument, 0, 'K'},
	{"cert", optional_argument, 0, 'C'},
	{"cacert", optional_argument, 0, 'A'},
	{"hostname", optional_argument, 0, 'H'},
	{"insecure", no_argument, 0, 'i'},
	{"debug", no_argument, 0, 'd'},
	{"help", no_argument, 0, 'h'},
	{0, 0, 0, 0}
      };

      int optind = 0;

      int c = getopt_long (argc, argv, "c:l:K:C:A:H:idh", longopts, &optind);
      if (c == -1)
	break;

      switch (c)
	{
	case 0:		/* set a flag, nothing else to do */
	  break;

	case 'c':
	  connectaddr = strdup (optarg);
	  break;

	case 'l':
	  listenaddr = strdup (optarg);
	  break;

	case 'K':
	  keyfile = strdup (optarg);
	  break;

	case 'C':
	  certfile = strdup (optarg);
	  break;

	case 'A':
	  cacertfile = strdup (optarg);
	  break;

	case 'H':
	  hostname = strdup (optarg);
	  break;

	case 'i':
	  insecure = 1;
	  break;

	case 'd':
	  debug++;
	  break;

	case 'h':
	  usage ();
	  exit (0);
	  break;

	default:
	  usage ();
	  exit (1);
	}
    }

  if (optind != argc || !connectaddr || !listenaddr)
    {
      usage ();
      exit (1);
    }

  if (!certfile && keyfile)
    certfile = strdup (keyfile);
}

void
setsignalmasks ()
{
  struct sigaction sa;
  /* Set up the structure to specify the new action. */
  memset (&sa, 0, sizeof (struct sigaction));
  sa.sa_handler = handlesignal;
  sigemptyset (&sa.sa_mask);
  sa.sa_flags = 0;
  sigaction (SIGINT, &sa, NULL);
  sigaction (SIGTERM, &sa, NULL);

  memset (&sa, 0, sizeof (struct sigaction));
  sa.sa_handler = SIG_IGN;
  sa.sa_flags = SA_RESTART;
  sigaction (SIGPIPE, &sa, NULL);
}

int
main (int argc, char **argv)
{
  processoptions (argc, argv);

  setsignalmasks ();

  if (crypto_init ())
    exit (1);

  runlistener ();

  free (connectaddr);
  free (listenaddr);
  free (keyfile);
  free (certfile);
  free (cacertfile);
  free (hostname);

  exit (0);
}
