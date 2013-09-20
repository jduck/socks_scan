/*
 * socks5.c: SOCKS v5 proxy negotiation routines
 * 
 * currently supports AUTH_NONE and AUTH_PASSWD
 *
 * written by Joshua J. Drake (jduck@EFNet, socks_scan@qoop.org)
 * 
 * 1998-11-04 	started
 * 1999-11-14	fixed some bugs
 * 2000-09-26	added passwd auth
 * 2002-01-13	redesigned to be more asyncronous
 * 2002-10-02 	added error buffer parameters
 * 		added bounds checking to user/pass length
 */

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <errno.h>

#include <arpa/inet.h>

#include "socks5.h"

char *
socks5_error(int cd)
{
   static char ebuf[128];
   
   switch (cd)
     {
      case SOCKS5_ERR_FAIL:
	strcpy(ebuf, "Rejected or failed");
	break;
      case SOCKS5_ERR_AUTHORIZE:
	strcpy(ebuf, "Connection not allowed by ruleset");
	break;
      case SOCKS5_ERR_NETUNREACH:
	strcpy(ebuf, "Network unreachable");
	break;
      case SOCKS5_ERR_HOSTUNREACH:
	strcpy(ebuf, "Host unreachable");
	break;
      case SOCKS5_ERR_CONNREF:
	strcpy(ebuf, "Connection refused");
	break;
      case SOCKS5_ERR_TTLEXP:
	strcpy(ebuf, "Time to live expired");
	break;
      case SOCKS5_ERR_BADCMD:
	strcpy(ebuf, "Bad command");
	break;
      case SOCKS5_ERR_BADADDR:
	strcpy(ebuf, "Bad address");
	break;
      default:
	sprintf(ebuf, "Unknown error #%d", cd);
     }
   return ebuf;
}

/*
 * send a socks auth request
 */
int
socks5_send_auth_req(s, eb, ebl)
   int s;
   char *eb;
   unsigned int ebl;
{
   char req[512], *p;
   int rl, wl;
   
#ifdef SOCKS_DEBUG
   fprintf(stderr, "SOCKS5: sending supported auth type request\n");
#endif
   p = req;
   *p++ = SOCKS5_VERSION;
   *p++ = 2;
   *p++ = SOCKS5_AUTH_NONE;
   *p++ = SOCKS5_AUTH_PASSWD;
   
   rl = (int)(p - req);
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
	       snprintf(eb, ebl-1, "error writing auth proposal: %s", strerror(errno));
	     else
	       snprintf(eb, ebl-1, "only wrote %d bytes of auth proposal", wl);
	     eb[ebl-1] = '\0';
	  }
#ifdef SOCKS_DEBUG
	fprintf(stderr, "SOCKS5: %s\n", eb);
#endif
	return 0;
     }
   return 1;
}

/*
 * read/analyze a socks response
 */
int
socks5_recv_auth_rep(s, eb, ebl)
   int s;
   char *eb;
   unsigned int ebl;
{
   char rep[128];
   int rl;

#ifdef SOCKS_DEBUG
   fprintf(stderr, "SOCKS5: reading supported auth type response\n");
   if (!eb)
     {
	eb = rep;
	ebl = sizeof(rep);
     }
#endif
   if ((rl = read(s, rep, sizeof(rep))) < 1)
     {
	if (eb)
	  {
	     snprintf(eb, ebl-1, "error reading auth reply: %s",
		      rl == 0 ? "Remote end closed connection" : strerror(errno));
	     eb[ebl-1] = '\0';
	  }
#ifdef SOCKS_DEBUG
	fprintf(stderr, "SOCKS5: %s\n", eb);
#endif
        return 0;
     }
   if (rep[0] == 0 && rep[1] == 0x5b)
     {
	if (eb)
	  {
	     strncpy(eb, "this is a SOCKS v4 server!", ebl-1);
	     eb[ebl-1] = '\0';
	  }
#ifdef SOCKS_DEBUG
	fprintf(stderr, "SOCKS5: %s\n", eb);
#endif
	return 0;
     }
#ifdef SOCKS_DEBUG
   fprintf(stderr, "SOCKS5: selected auth type: 0x%x\n", rep[1]);
#endif
   
   /* report server desired authentication (if not none) */
   switch (rep[1])
     {
      case SOCKS5_AUTH_NONE:
	return 1;
	/* all done heheh */
      case SOCKS5_AUTH_PASSWD:
	return 2;
	/* :) */
      default:
	if (eb)
	  {
	     snprintf(eb, ebl-1, "server wants type 0x%x authentication", rep[1]);
	     eb[ebl-1] = '\0';
	  }
#ifdef SOCKS_DEBUG	
	fprintf(stderr, "SOCKS5: %s\n", eb);
#endif
     }
   /* not reached... */
   return 0;
}

/*
 * send the username/password
 */
int
socks5_send_userpass_req(s, user, pass, eb, ebl)
   int s;
   char *user, *pass, *eb;
   unsigned int ebl;
{
   char req[768], *p;
   int rl, wl;
   
#ifdef SOCKS_DEBUG
   if (!eb)
     {
	eb = req;
	ebl = sizeof(req);
     }
#endif
   /* check out username and password */
   if (!user || !*user || strlen(user) > 255
       || !pass || !*pass || strlen(pass) > 255)
     {
	if (eb)
	  {
	     strncpy(eb, "missing or invalid user/pass", ebl-1);
	     eb[ebl-1] = '\0';
	  }
#ifdef SOCKS_DEBUG
	fprintf(stderr, "SOCKS5: %s\n", eb);
#endif
	return 0;
     }
#ifdef SOCKS_DEBUG
   fprintf(stderr, "SOCKS5: sending user/pass request: %s/%s\n", user,pass);
#endif
   p = req;
   *(p++) = 0x01;
   *(p++) = (char)strlen(user);
   strcpy(p, user);
   p += strlen(user);
   *(p++) = strlen(pass);
   strcpy(p, pass);
   p += strlen(pass);
   rl = (int)(p - req);
   
   if ((wl = write(s, req, rl)) != rl)
     {
	if (eb)
	  {
	     if (wl == -1)
	       snprintf(eb, ebl-1, "error writing user/pass request: %s", strerror(errno));
	     else
	       snprintf(eb, ebl-1, "only wrote %d bytes of user/pass request", wl);
	     eb[ebl-1] = '\0';
	  }
#ifdef SOCKS_DEBUG
	fprintf(stderr, "SOCKS5: %s\n", eb);
#endif
	return 0;
     }
   return 1;
}

/*
 * read the user/pass response
 */
int
socks5_recv_userpass_rep(s, eb, ebl)
   int s;
   char *eb;
   unsigned int ebl;
{
   char rep[128];
   int rl;
   
#ifdef SOCKS_DEBUG
   fprintf(stderr, "SOCKS5: reading user/pass response\n");
   if (!eb)
     {
	eb = rep;
	ebl = sizeof(rep);
     }
#endif
   if ((rl = read(s, rep, sizeof(rep))) == -1)
     {
	if (eb)
	  {
	     snprintf(eb, ebl-1, "error reading user/pass reply: %s",
		      rl == 0 ? "Remote end closed connection" : strerror(errno));
	     eb[ebl-1] = '\0';
	  }
#ifdef SOCKS_DEBUG
	fprintf(stderr, "SOCKS5: %s\n", eb);
#endif
	return 0;
     }
   if (rep[1] != 0)
     {
	if (eb)
	  {
	     strncpy(eb, "invalid user/pass", ebl-1);
	     eb[ebl-1] = '\0';
	  }
#ifdef SOCKS_DEBUG
	fprintf(stderr, "SOCKS5: %s\n", eb);
#endif
	return 0;
     }
#ifdef SOCKS_DEBUG
   fprintf(stderr, "SOCKS5: user/pass accepted\n");
#endif
   return 1;
}


/*
 * send a socks5 connect request...
 */
int
socks5_send_connect_req(s, server, eb, ebl)
   int s;
   struct sockaddr_in server;
   char *eb;
   unsigned int ebl;
{
   char req[128], *p;
   int wl, rl;
   
   p = req;
   *p++ = SOCKS5_VERSION;
   *p++ = SOCKS5_CMD_CONNECT;
   *p++ = 0;
   *p++ = SOCKS5_ATYP_IPV4ADDR;
   memcpy(p, &(server.sin_addr.s_addr), 4);
   p += 4;
   memcpy(p, &(server.sin_port), 2);
   p += 2;
   
#ifdef SOCKS_DEBUG
   fprintf(stderr, "SOCKS5: Connecting through proxy to: %s:%u...\n",
	   inet_ntoa(server.sin_addr), ntohs(server.sin_port));
   if (!eb)
     {
	eb = req;
	ebl = sizeof(req);
     }
#endif
   rl = (int)(p - req);
   if ((wl = write(s, req, rl)) != 10)
     {
	if (eb)
	  {
	     if (wl == -1)
	       snprintf(eb, ebl-1, "error writing connect request: %s", strerror(errno));
	     else
	       snprintf(eb, ebl-1, "only wrote %d bytes of connect request", wl);
	     eb[ebl-1] = '\0';
	  }
#ifdef SOCKS_DEBUG
	fprintf(stderr, "SOCKS5: %s\n", eb);
#endif
	return 0;
     }
   return 1;
}


/*
 * receive a socks5 connect response
 */
int
socks5_recv_connect_rep(s, eb, ebl)
   int s;
   char *eb;
   unsigned int ebl;
{
   char req[128];
   int rl;
#ifdef SOCKS_DEBUG
   char tb[256];
   struct sockaddr_in sin;
   unsigned short ts;
   
   fprintf(stderr, "SOCKS5: reading connect response\n");
   if (!eb)
     {
	eb = tb;
	ebl = sizeof(tb);
     }
#endif
   if ((rl = read(s, req, sizeof(req))) < 1)
     {
	if (eb)
	  {
	     snprintf(eb, ebl-1, "error reading connect reply: %s",
		      rl == 0 ? "Remote end closed connection" : strerror(errno));
	     eb[ebl-1] = '\0';
	  }
#ifdef SOCKS_DEBUG
	fprintf(stderr, "SOCKS5: %s\n", eb);
#endif
	return 0;
     }
   if (req[0] != SOCKS5_VERSION)
     {
	if (eb)
	  {
	     strncpy(eb, "this is not a SOCKS v5 proxy", ebl-1);
	     eb[ebl-1] = '\0';
	  }
#ifdef SOCKS_DEBUG
	fprintf(stderr, "SOCKS5: %s\n", eb);
#endif
	return 0;
     }
   if (req[1] != SOCKS5_ERR_NOERR)
     {
	if (eb)
	  {
	     snprintf(eb, ebl-1, "unable to connect through proxy: %s", socks5_error(req[1]));
	     eb[ebl-1] = '\0';
	  }
#ifdef SOCKS_DEBUG
	fprintf(stderr, "SOCKS5: %s\n", eb);
#endif
	return 0;
     }
   /*
    * parse the rest of the response..
    */
   switch (req[3])
     {
      case 1:
#ifdef SOCKS_DEBUG
	memcpy(&(sin.sin_addr.s_addr), req+4, sizeof(sin.sin_addr.s_addr));
	memcpy(&(sin.sin_port), req+8, sizeof(sin.sin_port));
	fprintf(stderr, "SOCKS5: bounce successful, your address will be: %s:%d\n",
		 inet_ntoa(sin.sin_addr), ntohs(sin.sin_port));
#endif
	break;
      case 3:
#ifdef SOCKS_DEBUG
	/* parse out the remote address */
	ts = (u_short)req[4];
	if (ts > sizeof(tb)-1)
	  {
	     memcpy(tb, req+5, sizeof(tb)-1);
	     tb[sizeof(tb)-1] = '\0';
	  }
	else
	  {
	     memcpy(tb, req+5, ts);
	     tb[ts] = '\0';
	  }
	/* and port */
	memcpy(&(sin.sin_port), req + ts + 5, sizeof(sin.sin_port));
	fprintf(stderr, "SOCKS5: bounce successful, your address will be: %s:%d\n",
		 tb, ntohs(sin.sin_port));
#endif
	break;
      case 4:
#ifdef SOCKS_DEBUG
	/* don't report address of ipv6 addresses. */
	fprintf(stderr, "SOCKS bounce successful.");
#endif
	break;
      default:
	if (eb)
	  {
	     snprintf(eb, ebl-1, "unknown address type: 0x%x", req[3]);
	     eb[ebl-1] = '\0';
	  }
#ifdef SOCKS_DEBUG
	fprintf(stderr, "SOCKS5: %s\n", eb);
#endif
	return 0;
     }
   return 1;
}


/*
 * try to negotiate a SOCKS5 connection. (with the socket/username, to the server)
 */
int
socks5_connect(s, server, user, pass, eb, ebl)
   int s;
   struct sockaddr_in server;
   char *user, *pass, *eb;
   unsigned int ebl;
{
   /* propose desired authentication */
   if (!socks5_send_auth_req(s, eb, ebl))
     return 0;

   /* get response */
   switch (socks5_recv_auth_rep(s, eb, ebl))
     {
      case 1:
	/* no-auth */
	break;
      case 2:
	if (!socks5_send_userpass_req(s, user, pass, eb, ebl))
	  return 0;
	if (!socks5_recv_userpass_rep(s, eb, ebl))
	  return 0;
	break;
      default:
	return 0;
     }
   
   /* try to bounce to target */
   if (!socks5_send_connect_req(s, server, eb, ebl))
     return 0;
   
   /* read the response... */
   if (!socks5_recv_connect_rep(s, eb, ebl))
     return 0;
   return 1;
}
