/*
 * socks4.c: SOCKS v4 proxy negotiation code
 *
 * written by Joshua J. Drake (jduck@EFNet, socks_scan@qoop.org)
 * 
 * 1998-11-04 	started 
 * 1999-11-14	fixed bugs
 * 2002-09-30	re-arranged for asyncronous use
 * 2002-10-02	added error buffer parameters
 * 		fixed some possible out of bounds writes
 */

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include <arpa/inet.h>

#include "socks4.h"

/*
 * socks4_error
 * 
 * translate a SOCKS4 error byte into a human readable error message
 */
char *
socks4_error(int cd)
{
   static char ebuf[128];
   
   switch (cd)
     {
      case 91:
	strcpy(ebuf, "Rejected or failed");
	break;
      case 92:
	strcpy(ebuf, "Unable to connect to identd on client");
	break;
      case 93:
	strcpy(ebuf, "Client identd response != reported username");
	break;
      default:
	sprintf(ebuf, "Unknown error #%d", cd);
	break;
     }
   return ebuf;
}


/*
 * send a socks4 connect request
 */
int
socks4_send_connect_req(s, srv, user, eb, ebl)
   int s;
   struct sockaddr_in srv;
   char *user, *eb;
   unsigned int ebl;
{
   char req[512], *p;
   int wl, rl;
   
   p = req;
   *(p++) = SOCKS4_VERSION;
   *(p++) = SOCKS_CONNECT;
   memcpy(p, &srv.sin_port, 2);
   p += 2;
   memcpy(p, &srv.sin_addr.s_addr, 4);
   p += 4;
   /* copy up to the remainder of the request buffer,
    * leaving space for a null.. */
   rl = sizeof(req) - (int)(p - req) - 1;
   if (strlen(user) < rl)
     rl = strlen(user);
   strncpy(p, user, rl);
   p += rl;
   *p++ = '\0';
   rl = (int)(p - req);

#ifdef SOCKS_DEBUG
   fprintf(stderr, "SOCKS4: Connecting through proxy to: %s:%u...\n",
	  inet_ntoa(srv.sin_addr), ntohs(srv.sin_port));
#endif

   if ((wl = write(s, req, rl)) != rl)
     {
#ifdef SOCKS_DEBUG
	if (!eb)
	  {
	     eb = req;
	     ebl = sizeof(req);
	  }
#endif
	if (eb)
	  {
	     if (wl == -1)
	       snprintf(eb, ebl-1, "error writing connect request: %s", strerror(errno));
	     else
	       snprintf(eb, ebl-1, "only wrote %d bytes of connect request!", wl);
	     eb[ebl-1] = '\0';
	  }
#ifdef SOCKS_DEBUG
	fprintf(stderr, "SOCKS4: %s\n", eb);
#endif
	return 0;
     }
   return 1;
}


/*
 * read a socks4 connect reply
 */
int
socks4_recv_connect_rep(s, eb, ebl)
   int s;
   char *eb;
   unsigned int ebl;
{
   char rep[128];
   int rl;
   
#ifdef SOCKS_DEBUG
   /* check the error buffer.. */
   if (!eb)
     {
	eb = rep;
	ebl = sizeof(rep);
     }
#endif
   if ((rl = read(s, rep, sizeof(rep))) <= 0)
     {
	if (eb)
	  {
	     snprintf(eb, ebl-1, "error reading connect reply: %s", 
		      rl == 0 ? "Remote end closed connection" : strerror(errno));
	     eb[ebl-1] = '\0';
	  }
#ifdef SOCKS_DEBUG
	fprintf(stderr, "SOCKS4: %s\n", eb);
#endif
	return 0;
     }
   if (rep[1] != 90)
     {
	if (eb)
	  {
	     snprintf(eb, ebl-1, "unable to connect through proxy: %s", socks4_error((int)rep[1]));
	     eb[ebl-1] = '\0';
	  }
#ifdef SOCKS_DEBUG
        fprintf(stderr, "SOCKS4: %s\n", eb);
#endif
        return 0;
     }
   return 1;
}


/*
 * try to negotiate a SOCKS4 connection.
 */
int
socks4_connect(s, server, user, ebuf, ebl)
   int s;
   struct sockaddr_in server;
   char *user, *ebuf;
   unsigned int ebl;
{
   if (!socks4_send_connect_req(s, server, user, ebuf, ebl))
     return 0;
   
   if (!socks4_recv_connect_rep(s, ebuf, ebl))
     return 0;
   return 1;
}
