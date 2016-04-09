#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <netdb.h>
#include <unistd.h>

#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include <gnutls/x509.h>
#include <gnutls/abstract.h>

#include "crypto.h"
#include "tlsproxy.h"
#include "buffer.h"

#define MAX_CERTS 10

static volatile sig_atomic_t rxsigquit = 0;

typedef struct tlssession
{
  gnutls_certificate_credentials_t creds;
  gnutls_session_t session;
  char *hostname;
} tlssession_t;

#define BUF_SIZE 65536
#define BUF_HWM ((BUF_SIZE*3)/4)

/* From (public domain) example file in GNUTLS
 *
 * This function will try to verify the peer's certificate, and
 * also check if the hostname matches, and the activation, expiration dates.
 */
static int
verify_certificate_callback (gnutls_session_t session)
{
  unsigned int status;
  const gnutls_datum_t *cert_list;
  unsigned int cert_list_size;
  int ret;
  gnutls_x509_crt_t cert;
  tlssession_t *s;

  /* read session pointer */
  s = (tlssession_t *) gnutls_session_get_ptr (session);

  /* This verification function uses the trusted CAs in the credentials
   * structure. So you must have installed one or more CA certificates.
   */
  ret = gnutls_certificate_verify_peers2 (session, &status);
  if (ret < 0)
    {
      if (debug)
	fprintf (stderr, "Error\n");
      return GNUTLS_E_CERTIFICATE_ERROR;
    }

  if (status & GNUTLS_CERT_INVALID)
    if (debug)
      fprintf (stderr, "The certificate is not trusted.\n");

  if (status & GNUTLS_CERT_SIGNER_NOT_FOUND)
    if (debug)
      fprintf (stderr, "The certificate hasn't got a known issuer.\n");

  if (status & GNUTLS_CERT_REVOKED)
    if (debug)
      fprintf (stderr, "The certificate has been revoked.\n");

  if (status & GNUTLS_CERT_EXPIRED)
    if (debug)
      fprintf (stderr, "The certificate has expired\n");

  if (status & GNUTLS_CERT_NOT_ACTIVATED)
    if (debug)
      fprintf (stderr, "The certificate is not yet activated\n");

  if (status)
    return GNUTLS_E_CERTIFICATE_ERROR;

  if (gnutls_certificate_type_get (session) != GNUTLS_CRT_X509)
    return GNUTLS_E_CERTIFICATE_ERROR;

  if (gnutls_x509_crt_init (&cert) < 0)
    {
      if (debug)
	fprintf (stderr, "error in initialization\n");
      return GNUTLS_E_CERTIFICATE_ERROR;
    }

  cert_list = gnutls_certificate_get_peers (session, &cert_list_size);
  if (cert_list == NULL)
    {
      if (debug)
	fprintf (stderr, "No certificate was found!\n");
      return GNUTLS_E_CERTIFICATE_ERROR;
    }

  /* check only the first certificate - seems to be what curl does */
  if (gnutls_x509_crt_import (cert, &cert_list[0], GNUTLS_X509_FMT_DER) < 0)
    {
      if (debug)
	fprintf (stderr, "error parsing certificate\n");
      return GNUTLS_E_CERTIFICATE_ERROR;
    }

  if (s->hostname && *s->hostname)
    {
      if (!gnutls_x509_crt_check_hostname (cert, s->hostname))
	{
	  if (debug)
	    fprintf (stderr,
		     "The certificate's owner does not match hostname '%s'\n",
		     s->hostname);
	  return GNUTLS_E_CERTIFICATE_ERROR;
	}
    }

  gnutls_x509_crt_deinit (cert);

  if (debug)
    fprintf (stderr, "Peer passed certificate verification\n");

  /* notify gnutls to continue handshake normally */
  return 0;
}

tlssession_t *
newtlssession (int isserver, char *hn)
{
  int ret;
  tlssession_t *s = calloc (1, sizeof (tlssession_t));

  if (hn)
    s->hostname = strdup (hn);

  if (gnutls_certificate_allocate_credentials (&s->creds) < 0)
    {
      fprintf (stderr, "Certificate allocation memory error\n");
      goto error;
    }

  if (cacertfile != NULL)
    {
      ret =
	gnutls_certificate_set_x509_trust_file (s->creds, cacertfile,
						GNUTLS_X509_FMT_PEM);
      if (ret < 0)
	{
	  fprintf (stderr, "Error setting the x509 trust file: %s\n",
		   gnutls_strerror (ret));
	  goto error;
	}

      if (!insecure)
	{
	  gnutls_certificate_set_verify_function (s->creds,
						  verify_certificate_callback);
	  gnutls_certificate_set_verify_flags (s->creds,
					       GNUTLS_VERIFY_ALLOW_X509_V1_CA_CRT);
	}
    }

  if (certfile != NULL && keyfile != NULL)
    {
      ret =
	gnutls_certificate_set_x509_key_file (s->creds, certfile, keyfile,
					      GNUTLS_X509_FMT_PEM);

      if (ret < 0)
	{
	  fprintf (stderr,
		   "Error loading certificate or key file: %s\n",
		   gnutls_strerror (ret));
	  goto error;
	}
    }

  if (isserver)
    {
      ret = gnutls_init (&s->session, GNUTLS_SERVER);
    }
  else
    {
      ret = gnutls_init (&s->session, GNUTLS_CLIENT);
    }
  if (ret < 0)
    {
      fprintf (stderr, "Cannot initialize GNUTLS session: %s\n",
	       gnutls_strerror (ret));
      goto error;
    }

  gnutls_session_set_ptr (s->session, (void *) s);

  ret = gnutls_set_default_priority (s->session);
  if (ret < 0)
    {
      fprintf (stderr, "Cannot set default GNUTLS session priority: %s\n",
	       gnutls_strerror (ret));
      goto error;
    }
  ret = gnutls_credentials_set (s->session, GNUTLS_CRD_CERTIFICATE, s->creds);
  if (ret < 0)
    {
      fprintf (stderr, "Cannot set session GNUTL credentials: %s\n",
	       gnutls_strerror (ret));
      goto error;
    }

  if (isserver)
    {
      /* requests but does not check a client certificate */
      gnutls_certificate_server_set_request (s->session, GNUTLS_CERT_REQUEST);
    }


  return s;

error:
  if (s->session)
    gnutls_deinit (s->session);
  free (s);
  return NULL;
}

void
closetlssession (tlssession_t * s)
{
  if (s->session)
    gnutls_deinit (s->session);
  free (s->hostname);
  free (s);
}

int
crypto_init ()
{
  int ret = gnutls_global_init ();
  if (ret < 0)
    {
      fprintf (stderr, "Unable to initialize GNUTLS library: %s\n",
	       gnutls_strerror (ret));
      return -1;
    }
  if (debug)
    {
      gnutls_global_set_log_level (10);
      /*
         gnutls_global_set_log_function (...);
       */
    }

  return 0;
}

void
handlesignal (int sig)
{
  switch (sig)
    {
    case SIGINT:
    case SIGTERM:
      rxsigquit++;
      break;
    default:
      break;
    }
}

int
mainloop (int cryptfd, int plainfd, tlssession_t * session)
{
  fd_set readfds;
  fd_set writefds;
  int maxfd;
  int tls_wr_interrupted = 0;
  int plainEOF = FALSE;
  int cryptEOF = FALSE;
  int ret;

  buffer_t *plainToCrypt = bufNew (BUF_SIZE, BUF_HWM);
  buffer_t *cryptToPlain = bufNew (BUF_SIZE, BUF_HWM);

  /* set it up to work with our FD */
  gnutls_transport_set_ptr (session->session,
			    (gnutls_transport_ptr_t) (intptr_t) cryptfd);


  /* Now do the handshake */
  ret = gnutls_handshake (session->session);
  if (ret < 0)
    {
      fprintf (stderr, "TLS handshake failed: %s\n", gnutls_strerror (ret));
      goto error;
    }

  maxfd = (plainfd > cryptfd) ? plainfd + 1 : cryptfd + 1;

  while ((!plainEOF || !cryptEOF) && !rxsigquit)
    {
      struct timeval timeout;
      int result;
      int selecterrno;
      int wait = TRUE;

      FD_ZERO (&readfds);
      FD_ZERO (&writefds);

      size_t buffered = gnutls_record_check_pending (session->session);
      if (buffered)
	wait = FALSE;		/* do not wait for select to return if we have buffered data */

      if (plainEOF)
	{
	  /* plain text end has closed, but me may still have
	   * data yet to write to the crypt end */
	  if (bufIsEmpty (plainToCrypt) && !tls_wr_interrupted)
	    {
	      cryptEOF = TRUE;
	      break;
	    }
	}
      else
	{
	  if (!bufIsEmpty (cryptToPlain))
	    FD_SET (plainfd, &writefds);
	  if (!bufIsOverHWM (plainToCrypt))
	    FD_SET (plainfd, &readfds);
	}

      if (cryptEOF)
	{
	  /* crypt end has closed, but me way still have data to
	   * write from the crypt buffer */
	  if (bufIsEmpty (cryptToPlain) && !buffered)
	    {
	      plainEOF = TRUE;
	      break;
	    }
	}
      else
	{
	  if (!bufIsEmpty (plainToCrypt) || tls_wr_interrupted)
	    FD_SET (cryptfd, &writefds);
	  if (!bufIsOverHWM (cryptToPlain))
	    FD_SET (cryptfd, &readfds);
	}

      /* Repeat select whilst EINTR happens */
      do
	{
	  timeout.tv_sec = wait ? 1 : 0;
	  timeout.tv_usec = 0;
	  result = select (maxfd, &readfds, &writefds, NULL, &timeout);

	  selecterrno = errno;
	}
      while ((result == -1) && (selecterrno == EINTR) && !rxsigquit);
      if (rxsigquit)
	break;

      if (FD_ISSET (plainfd, &readfds))
	{
	  fprintf (stderr, "[DEBUG] Read plain\n");
	  /* we can read at least one byte */
	  void *addr = NULL;
	  /* get a span of characters to write to the
	   * buffer. As the empty portion may wrap the end of the
	   * circular buffer this might not be all we could read.
	   */
	  ssize_t len = bufGetWriteSpan (plainToCrypt, &addr);
	  if (len > 0)
	    {
	      ssize_t ret;
	      do
		{
		  ret = read (plainfd, addr, (size_t) len);
		}
	      while ((ret < 0) && (errno == EINTR) && !rxsigquit);
	      if (rxsigquit)
		break;
	      if (ret < 0)
		{
		  fprintf (stderr, "Error on read from plain socket: %m\n");
		  goto error;
		}
	      if (ret == 0)
		{
		  plainEOF = TRUE;
		}
	      else
		{
		  bufDoneWrite (plainToCrypt, ret);	/* mark ret bytes as written to the buffer */
		}
	    }
	}

      if (FD_ISSET (plainfd, &writefds))
	{
	  fprintf (stderr, "[DEBUG] Write plain\n");
	  /* we can write at least one byte */
	  void *addr = NULL;
	  /* get a span of characters to read from the buffer
	   * as the full portion may wrap the end of the circular buffer
	   * this might not be all we have to write.
	   */
	  ssize_t len = bufGetReadSpan (cryptToPlain, &addr);
	  if (len > 0)
	    {
	      ssize_t ret;
	      do
		{
		  ret = write (plainfd, addr, (size_t) len);
		}
	      while ((ret < 0) && (errno == EINTR) && !rxsigquit);
	      if (rxsigquit)
		break;
	      if (ret < 0)
		{
		  fprintf (stderr, "Error on write to plain socket: %m\n");
		  goto error;
		}
	      bufDoneRead (cryptToPlain, ret);	/* mark ret bytes as read from the buffer */
	    }
	}

      if (FD_ISSET (cryptfd, &readfds) || buffered)
	{
	  fprintf (stderr, "[DEBUG] Read crypt\n");
	  /* we can read at least one byte */
	  void *addr = NULL;
	  /* get a span of characters to write to the
	   * buffer. As the empty portion may wrap the end of the
	   * circular buffer this might not be all we could read.
	   */
	  ssize_t len = bufGetWriteSpan (cryptToPlain, &addr);
	  if (len > 0)
	    {
	      ssize_t ret;
	      do
		{
		  ret =
		    gnutls_record_recv (session->session, addr, (size_t) len);
		}
	      while (ret == GNUTLS_E_INTERRUPTED && !rxsigquit);
	      /* do not loop on GNUTLS_E_AGAIN - this means we'd block so we'd loop for
	       * ever
	       */
	      if (rxsigquit)
		break;
	      if (ret < 0 && ret != GNUTLS_E_AGAIN)
		{
		  fprintf (stderr, "Error on read from crypt socket: %s\n",
			   gnutls_strerror (ret));
		  goto error;
		}
	      if (ret == 0)
		{
		  cryptEOF = TRUE;
		}
	      else
		{
		  bufDoneWrite (cryptToPlain, ret);	/* mark ret bytes as written to the buffer */
		}
	    }
	}

      if (FD_ISSET (cryptfd, &writefds))
	{
	  fprintf (stderr, "[DEBUG] Write crypt\n");
	  /* we can write at least one byte */
	  void *addr = NULL;
	  /* get a span of characters to read from the buffer
	   * as the full portion may wrap the end of the circular buffer
	   * this might not be all we have to write.
	   */
	  ssize_t len = bufGetReadSpan (plainToCrypt, &addr);
	  if (len > 0)
	    {
	      ssize_t ret;
	      do
		{
		  if (tls_wr_interrupted)
		    {
		      ret = gnutls_record_send (session->session, NULL, 0);
		    }
		  else
		    {
		      ret = gnutls_record_send (session->session, addr, len);
		    }
		}
	      while (ret == GNUTLS_E_INTERRUPTED && !rxsigquit);
	      if (rxsigquit)
		break;
	      if (ret == GNUTLS_E_AGAIN)
		{
		  /* we need to call this again with NULL parameters
		   * as it blocked
		   */
		  tls_wr_interrupted = TRUE;
		}
	      else if (ret < 0)
		{
		  fprintf (stderr, "Error on write to crypto socket: %s\n",
			   gnutls_strerror (ret));
		  goto error;
		}
	      bufDoneRead (plainToCrypt, ret);	/* mark ret bytes as read from the buffer */
	    }
	}
    }

  ret = 0;
  fprintf (stderr, "[DEBUG] Normal exit\n");
  goto freereturn;

error:
  fprintf (stderr, "[DEBUG] Error exit\n");
  ret = -1;

freereturn:
  gnutls_bye (session->session, GNUTLS_SHUT_RDWR);
  shutdown (plainfd, SHUT_RDWR);
  bufFree (plainToCrypt);
  bufFree (cryptToPlain);
  return ret;
}
