/*
 * socks_scan.c:
 * 
 * This program will scan for SOCKS v4 and v5 proxies from a number
 * of different sources.
 *
 * written by Joshua J. Drake (jduck@EFNet, socks_scan@qoop.org)
 *
 * 2002-10-01 	started initial coding, adapted socks[45].c from old stuff
 * 2002-10-02 	got it working with both socks4 and socks5 w/o auth
 */
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/select.h>

#include "socks4.h"
#include "socks5.h"

#include "targets.h"
#include "args.h"

#include "nsock_tcp.h"


#define SOCKS_4_VERSTR 		"v4"
#define SOCKS_5_VERSTR 		"v5"


/* data types.. */
typedef struct
{
   int sd;
   nsocktcp_t nst;
   targlist_t *targ;
   time_t connect_time;
   time_t write_time;
} scanslot_t;


/* global options structure */
opts_t options;


/* function prototypes */
static void scan_targets(targlist_t *, unsigned int);

static targlist_t *get_fresh_target(targlist_t *);

static void clear_slot(scanslot_t *);
static int init_slot(scanslot_t *, targlist_t *, char *, int);

/*
 * check arguments and dispatch execution
 */
int
main(c, v)
   int c;
   char *v[];
{
   targlist_t *targets = NULL, *t;
   unsigned long ntarg;
   
   fprintf(stderr, 
	   "SOCKS v4 and v5 asyncronous parallel scanner version %s\n"
	   "written by Joshua J. Drake (jduck@EFNet, socks_scan@qoop.org)\n\n", 
	   VERSTR);
   /* check arguments */
   ntarg = parse_args(c, v, &targets);
   if (ntarg == 0)
     {
	fprintf(stderr, "no targets to scan!\n");
	return 1;
     }
   else if (ntarg == -1)
     return 1;

   if (options.verbose >= 1)
     fprintf(stderr, "loaded %lu targets to scan.\n", ntarg);
   
   /* possibly dump the entire target list */
   if (options.verbose >= 5)
     {
	unsigned int col = 0;
	
	fprintf(stderr, "targets:\n");
	for (t = targets; t; t = t->next)
	  {
	     fprintf(stderr, "%-19s:%u", inet_ntoa(t->ip), t->port);
	     if (col > 0 && (col % 3) == 0)
	       {
		  fprintf(stderr, "\n");
		  col = 0;
	       }
	     else 
	       col++;
	     fflush(stderr);
	  }
	fprintf(stderr, "\n");
     }

   /* dispatch execution */
   scan_targets(targets, ntarg);
   return 0;
}


/*
 * scan the targets..
 * 
 * attempt to scan X at a time..
 */
static void
scan_targets(targets, nt)
   targlist_t *targets;
   unsigned int nt;
{
   targlist_t *t;
   nsocktcp_t *n;
   scanslot_t *slots;
   unsigned int cncts = options.connects, tleft = nt, i;
   char ebuf[256];
   fd_set rd, wd;
   int maxs, sret;
   struct timeval tv;
   time_t start_time;
   
   /* less targets than slots? */
   if (nt < cncts)
     cncts = nt;
   /* get memory for the connection attempts */
   slots = (scanslot_t *)calloc(cncts, sizeof(scanslot_t));
   if (!slots)
     {
	fprintf(stderr, "Unable to allocate memory for %d scan slots.\n", cncts);
	return;
     }
   start_time = time(NULL);
   /* until all targets have been tested.. */
   while (tleft > 0)
     {
	/* zero the FD sets, timeval struct */
	FD_ZERO(&rd);
	FD_ZERO(&wd);
	tv.tv_sec = 0;
	tv.tv_usec = 500000;
	maxs = 0;
	
	/* always select stdin.. */
	FD_SET(fileno(stdin), &rd);
	
	/* check the slots for selection.. */
	for (i = 0; i < cncts; i++)
	  {
	     t = slots[i].targ;
	     if (!t)
	       continue;
	     if (((t->state & SPSS_4_CONNECTED)
		  && !(t->state & SPSS_4_DONE))
		 || ((t->state & SPSS_5_CONNECTED)
		     && !(t->state & SPSS_5_DONE)))
	       {
		  if (slots[i].sd > maxs)
		    maxs = slots[i].sd;
		  FD_SET(slots[i].sd, &rd);
		  FD_SET(slots[i].sd, &wd);
	       }
	  }
	maxs++;
	
	/* select! */
	sret = select(maxs+1, &rd, &wd, NULL, &tv);
	if (sret == -1)
	  {
	     perror("select failed");
	     return;
	  }

#ifdef SELECT_DEBUG
	printf("select says %d sockets are ready\n", sret);
	for (i = 0; i < cncts; i++)
	  {
	     if (FD_ISSET(slots[i].sd, &rd))
	       printf("socket #%d is ready for reading\n", slots[i].sd);
	     if (FD_ISSET(slots[i].sd, &wd))
	       printf("socket #%d is ready for writing\n", slots[i].sd);
	  }
#endif
	     
	/* if stdin is set, we give some status.. */
	if (FD_ISSET(fileno(stdin), &rd))
	  {
	     char tmp[1024];
	     
	     fprintf(stderr, "[scanned %u of %u in %lu seconds]\n",
		     nt - tleft, nt, time(NULL) - start_time);
	     /* clear stdin */
	     (void) read(fileno(stdin), tmp, sizeof(tmp));
	  }
	

	     
	/* check the slots.. */
	for (i = 0; i < cncts; i++)
	  {
	     /* nothing here??  we can fix that! */
	     if (!slots[i].targ)
	       {
		  if (init_slot(&slots[i], targets, ebuf, sizeof(ebuf)))
		    {
		       if (options.verbose >= 2)
			 printf("%3d   %-18s now occupied\n", i, inet_ntoa(slots[i].targ->ip));
		       continue;
		    }
	       }
	     /* still empty?  we must be out of targets! */
	     if (!slots[i].targ)
	       continue;
	     
	     /* convenience */
	     t = slots[i].targ;
	     n = &slots[i].nst;
	     
	     
	     
	     /* 
	      * if this slot is not yet connecting, initiate the connection..
	      */
	     if (!(t->state & SPSS_4_CONNECTING)
		 || ((t->state & SPSS_4_DONE) && !(t->state & SPSS_5_CONNECTING)))
	       {
		  char *vstr = SOCKS_4_VERSTR;

		  /* socks 4 or 5 pass? */
		  if (t->state & SPSS_4_DONE)
		    vstr = SOCKS_5_VERSTR;

		  /* try it */
		  slots[i].sd = nsock_tcp_connect(n, 0);
		  if (slots[i].sd < 0)
		    {
		       printf("%3d   %-18s %-4s connect failed: %s\n", i, inet_ntoa(t->ip), vstr, ebuf);
		       tleft--;
		       clear_slot(&slots[i]);
		       continue;
		    }
		  /* conneciton initiated, record the time and update the state */
		  if (options.verbose >= 2)
		    printf("%3d   %-18s %-4s connecting...\n", i, inet_ntoa(t->ip), vstr);
		  slots[i].connect_time = time(NULL);
		  if (t->state & SPSS_4_DONE)
		    t->state |= SPSS_5_CONNECTING;
		  else
		    t->state |= SPSS_4_CONNECTING;
		  continue;
	       }

	     
	     
	     
	     
	     /* 
	      * if this slot is not connected yet, check to see if it is now..
	      */
	     if (!(t->state & SPSS_4_CONNECTED))
	       {
		  switch (nsock_tcp_connected(slots[i].sd))
		    {
		     case 1:
		       /* cool it connected! */
		       if (options.verbose >= 2)
			 printf("%3d   %-18s %-4s connected!\n", i, inet_ntoa(t->ip), SOCKS_4_VERSTR);
		       t->state |= SPSS_4_CONNECTED;
		       
		       /* try to set the socket to blocking.. */
		       if (nsock_tcp_set_blocking(slots[i].sd, 0) < 0)
			 {
			    printf("%3d   %-18s %-4s unable to set to blocking: %s\n", i, inet_ntoa(t->ip), SOCKS_4_VERSTR, strerror(errno));
			    tleft--;
			    clear_slot(&slots[i]);
			    continue;
			 }
		       continue;
		     case -1:
		       /* eek, there was an error returned from nsock_tcp_connected() */
		       printf("%3d   %-18s %-4s unable to connect: %s\n", i, inet_ntoa(t->ip), SOCKS_4_VERSTR, strerror(errno));
		       tleft--;
		       clear_slot(&slots[i]);
		       continue;
		    }
		  
		  /* connection timeout? */
		  if ((time(NULL) - slots[i].connect_time) >= options.timeout)
		    {
		       printf("%3d   %-18s %-4s unable to connect: %s\n", i, inet_ntoa(t->ip), SOCKS_4_VERSTR, strerror(ETIMEDOUT));
		       tleft--;
		       clear_slot(&slots[i]);
		    }
		  continue;
	       }
	     
	     /*
	      * if this slot has not sent out the SOCKS v4 connection request yet, and writing will not block...
	      * proceed to attempt it..
	      */
	     if (!(t->state & SPSS_4_REQ_SENT)
		 && FD_ISSET(slots[i].sd, &wd))
	       {
		  /* attempt to send the connect request */
		  if (!socks4_send_connect_req(slots[i].sd, options.remote, options.username, ebuf, sizeof(ebuf)))
		    {
		       printf("%3d   %-18s %-4s %s\n", i, inet_ntoa(t->ip), SOCKS_4_VERSTR, ebuf);
		       tleft--;
		       clear_slot(&slots[i]);
		       continue;
		    }
		  /* cool we sent it!  set the write time and update the state */
		  if (options.verbose >= 2)
		    printf("%3d   %-18s %-4s connect request sent!\n", i, inet_ntoa(t->ip), SOCKS_4_VERSTR);
		  t->state |= SPSS_4_REQ_SENT;
		  slots[i].write_time = time(NULL);
	       }

	     /* if this slot has sent the socks4 connect reqest, and data is available,
	      * read the reply..
	      */
	     if (!(t->state & SPSS_4_REP_RECVD))
	       {
		  /* data is ready? */
		  if (FD_ISSET(slots[i].sd, &rd))
		    {
		       /* read the reply */
		       if (!socks4_recv_connect_rep(slots[i].sd, ebuf, sizeof(ebuf)))
			 {
			    printf("%3d   %-18s %-4s %s\n", i, inet_ntoa(t->ip), SOCKS_4_VERSTR, ebuf);
			    t->state |= SPSS_4_DONE;
			    t->state |= SPSS_4_REP_RECVD;
			    close(slots[i].sd);
			    continue;
			 }
		       /* cool it was successful! */
		       t->state |= SPSS_4_REP_RECVD;
		       t->state |= SPSS_4_DONE;
		       t->state |= SPSS_4_SUCCESSFUL;
		       printf("%3d   %-18s %-4s connection successful!\n", i, inet_ntoa(t->ip), SOCKS_4_VERSTR);
		       close(slots[i].sd);
		    }
		  /* perhaps it has been too long since our request was sent.. */
		  else if ((time(NULL) - slots[i].write_time) >= options.timeout)
		    {
		       printf("%3d   %-18s %-4s unable to read reply: %s\n", i, inet_ntoa(t->ip), SOCKS_4_VERSTR, strerror(ETIMEDOUT));
		       tleft--;
		       clear_slot(&slots[i]);
		    }
		  continue;
	       }
	     
	     
	     
	     
	     
	     
	     /* 
	      * if this slot is not connected yet, check to see if it is now..
	      */
	     if (!(t->state & SPSS_5_CONNECTED))
	       {
		  switch (nsock_tcp_connected(slots[i].sd))
		    {
		     case 1:
		       /* cool it connected! */
		       if (options.verbose >= 2)
			 printf("%3d   %-18s %-4s connected!\n", i, inet_ntoa(t->ip), SOCKS_5_VERSTR);
		       t->state |= SPSS_5_CONNECTED;
		       
		       /* try to set the socket to blocking.. */
		       if (nsock_tcp_set_blocking(slots[i].sd, 0) < 0)
			 {
			    printf("%3d   %-18s %-4s unable to set to blocking: %s\n", i, inet_ntoa(t->ip), SOCKS_5_VERSTR, strerror(errno));
			    tleft--;
			    clear_slot(&slots[i]);
			    continue;
			 }
		       continue;
		     case -1:
		       /* eek, there was an error returned from nsock_tcp_connected() */
		       printf("%3d   %-18s %-4s unable to connect: %s\n", i, inet_ntoa(t->ip), SOCKS_5_VERSTR, strerror(errno));
		       tleft--;
		       clear_slot(&slots[i]);
		       continue;
		    }
		  
		  /* connection timeout? */
		  if ((time(NULL) - slots[i].connect_time) >= options.timeout)
		    {
		       printf("%3d   %-18s %-4s unable to connect: %s\n", i, inet_ntoa(t->ip), SOCKS_5_VERSTR, strerror(ETIMEDOUT));
		       tleft--;
		       clear_slot(&slots[i]);
		    }
		  continue;
	       }
	     
	     /*
	      * if we have not negotiated a SOCKS v5 authentication method start that now.
	      */
	     if (!(t->state & SPSS_5_AUTH_REQ_SENT)
		 && FD_ISSET(slots[i].sd, &wd))
	       {
		  if (!socks5_send_auth_req(slots[i].sd, ebuf, sizeof(ebuf)))
		    {
		       printf("%3d   %-18s %-4s %s\n", i, inet_ntoa(t->ip), SOCKS_5_VERSTR, ebuf);
		       tleft--;
		       clear_slot(&slots[i]);
		       continue;
		    }
		  /* cool we sent it!  set the write time and update the state */
		  if (options.verbose >= 2)
		    printf("%3d   %-18s %-4s auth type request sent!\n", i, inet_ntoa(t->ip), SOCKS_5_VERSTR);
		  t->state |= SPSS_5_AUTH_REQ_SENT;
		  slots[i].write_time = time(NULL);
		  continue;
	       }
	     
	     /*
	      * if we have not read the AUTH type reply, do it now
	      */
	     if (!(t->state & SPSS_5_AUTH_REP_RECVD))
	       {
		  if (FD_ISSET(slots[i].sd, &rd))
		    {
		       /* read the auth reply */
		       int atyp = socks5_recv_auth_rep(slots[i].sd, ebuf, sizeof(ebuf));
		       
		       if (atyp == 0)
			 {
			    printf("%3d   %-18s %-4s %s\n", i, inet_ntoa(t->ip), SOCKS_5_VERSTR, ebuf);
			    t->state |= SPSS_5_DONE;
			    tleft--;
			    clear_slot(&slots[i]);
			    continue;
			 }
		       /* cool it was successful! */
		       t->state |= SPSS_5_AUTH_REP_RECVD;
		       if (atyp == 1)
			 {
			    t->state |= SPSS_5_AUTH_NONE_OK;
			    if (options.verbose >= 2)
			      printf("%3d   %-18s %-4s no authentication required!\n", i, inet_ntoa(t->ip), SOCKS_5_VERSTR);
			 }
		       else if (atyp == 2)
			 {
			    printf("%3d   %-18s %-4s user/pass authentication required!\n", i, inet_ntoa(t->ip), SOCKS_5_VERSTR);
			    t->state |= SPSS_5_AUTH_PASS_OK;
			    tleft--;
			    clear_slot(&slots[i]);
			 }
		    }
		  else if ((time(NULL) - slots[i].write_time) >= options.timeout)
		    {
		       printf("%3d   %-18s %-4s unable to read auth reply: %s\n", i, inet_ntoa(t->ip), SOCKS_5_VERSTR, strerror(ETIMEDOUT));
		       tleft--;
		       clear_slot(&slots[i]);
		    }
		  continue;
	       }
	     
	     /*
	      * attempt to send the socks5 connection request.. 
	      */
	     if (!(t->state & SPSS_5_REQ_SENT)
		 && FD_ISSET(slots[i].sd, &wd))
	       {
		  if (!socks5_send_connect_req(slots[i].sd, options.remote, ebuf, sizeof(ebuf)))
		    {
		       printf("%3d   %-18s %-4s %s\n", i, inet_ntoa(t->ip), SOCKS_5_VERSTR, ebuf);
		       tleft--;
		       clear_slot(&slots[i]);
		       continue;
		    }
		  /* cool we sent it!  set the write time and update the state */
		  if (options.verbose >= 2)
		    printf("%3d   %-18s %-4s connect request sent!\n", i, inet_ntoa(t->ip), SOCKS_5_VERSTR);
		  t->state |= SPSS_5_REQ_SENT;
		  slots[i].write_time = time(NULL);
	       }

	     /*
	      * attempt to read the socks5 connection reply...
	      */
	     if (!(t->state & SPSS_5_REP_RECVD))
	       {
		  /* data ready? */
		  if (FD_ISSET(slots[i].sd, &rd))
		    {
		       if (!socks5_recv_connect_rep(slots[i].sd, ebuf, sizeof(ebuf)))
			 {
			    printf("%3d   %-18s %-4s %s\n", i, inet_ntoa(t->ip), SOCKS_5_VERSTR, ebuf);
			    t->state |= SPSS_5_DONE;
			    tleft--;
			    clear_slot(&slots[i]);
			    continue;
			 }
		       /* cool it was successful! */
		       t->state |= SPSS_5_REP_RECVD;
		       printf("%3d   %-18s %-4s connection successful!\n", i, inet_ntoa(t->ip), SOCKS_5_VERSTR);
		       /* now this is done.. clear it */
		       tleft--;
		       clear_slot(&slots[i]);
		    }
		  else if ((time(NULL) - slots[i].write_time) >= options.timeout)
		    {
		       printf("%3d   %-18s %-4s unable to read connect reply: %s\n", i, inet_ntoa(t->ip), SOCKS_5_VERSTR, strerror(ETIMEDOUT));
		       tleft--;
		       clear_slot(&slots[i]);
		    }
		  continue;
	       }
	  }
     }
}

/*
 * get a target that has not started yet.
 */
static targlist_t *
get_fresh_target(tl)
   targlist_t *tl;
{
   targlist_t *t;
   static int more = 1;
   
   if (more)
     {
	for (t = tl; t; t = t->next)
	  {
	     if (t->state == 0)
	       return t;
	  }
	more = 0;
     }
   return (targlist_t *)0;
}


/*
 * clear a slot to be reused..
 */
static void
clear_slot(sl)
   scanslot_t *sl;
{
   sl->targ->state |= SPSS_FINISHED;
   sl->targ = (targlist_t *)0;
   if (sl->sd >= 0)
     close(sl->sd);
}


/*
 * initialize a slot..
 */
static int
init_slot(sl, targets, ebuf, el)
   scanslot_t *sl;
   targlist_t *targets;
   char *ebuf;
   int el;
{
   if ((sl->targ = get_fresh_target(targets)))
     {
	sl->targ->state |= SPSS_STARTED;
	/* initialize the nsock_tcp* data */
	sl->nst.tin.sin_addr = sl->targ->ip;
	sl->nst.tin.sin_port = htons(sl->targ->port);
	sl->nst.tin.sin_family = AF_INET;
	sl->nst.opt = NSTCP_NON_BLOCK;
	sl->nst.ebuf = ebuf;
	sl->nst.ebl = el;
	return 1;
     }
   return 0;
}
