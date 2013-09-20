/*
 * targets.c: scan target linked list implementation
 * 
 * written by Joshua J. Drake (jduck@EFNet, socks_scan@qoop.org)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>

#include <math.h>

#include "socks.h"

#include "args.h"
#include "targets.h"

#include "nsock_resolve.h"

// static void free_target(targlist_t **);
static int add_target_ip(targlist_t **, unsigned long);
static int find_in_list(targlist_t **, targlist_t **, unsigned long);

/*
 * load targets from a file (one per line expected) and
 * link them to the list
 */
unsigned int
load_targets_from_file(tl, fn)
   targlist_t **tl;
   char *fn;
{
   FILE *fp;
   char buf[512], *p;
   unsigned int nts = 0;
   
   /* try to open the file for reading */
   if (!(fp = fopen(fn, "r")))
     {
	if (options.verbose >= 1)
	  fprintf(stderr, "Unable to load targets from \"%s\": %s\n", fn, strerror(errno));
	return 0;
     }
   
   /* look for targets.. */
   while (fgets(buf, sizeof(buf), fp))
     {
	/* strip cr/lf from the end */
	if ((p = strchr(buf, '\r')))
	  *p = '\0';
	if ((p = strchr(buf, '\n')))
	  *p = '\0';
	
	/* empty line? */
	if (!buf[0])
	  continue;
	
	/* try to add it */
	nts += add_target(tl, buf);
     }
   fclose(fp);
   /* return the number of targets found */
   return nts;
}


/*
 * add a target to the linked list of targets to scan
 * 
 * targ can be an IP, Host, or cidr.. the appropriate
 * targets will be added..
 */
int
add_target(tl, targ)
   targlist_t **tl;
   char *targ;
{
   struct in_addr ip;
   unsigned int ntargs = 0;
   
   if (options.verbose >= 3)
     fprintf(stderr, "add_targ(tl, \"%s\");\n", targ);

   /* what kind of target did we get? */
   if (strchr(targ, '/'))
     {
	/* we got a cidr! */
	char *p = strchr(targ, '/'), *q;
	unsigned long mask, tul;
	struct in_addr base, end;
	
	/* try to get the base ip */
	*p++ = '\0';
	if (!inet_aton(targ, &base))
	  {
	     fprintf(stderr, "Invalid CIDR base: %s\n", targ);
	     return 0;
	  }
	/* check the mask out */
	tul = strtoul(p, &q, 0);
	if (*q || tul < 0 || tul > 32)
	  {
	     fprintf(stderr, "Invalid CIDR mask: %s\n", p);
	     return 0;
	  }
	/* if the mask is less than we mask off the base */
	if (tul < 32 && (tul == 0 || (tul % 8) == 0))
	  {
	     mask = (unsigned long)pow(2.0, (double)tul) - 1;
	     base.s_addr &= mask;
	  }
	/* is the cidr base invalid? */
	if (tul < 32 && (ntohl(base.s_addr) << tul) != 0)
	  {
	     fprintf(stderr, "Invalid CIDR base: %s\n", targ);
	     return 0;
	  }
	/* setup the end ip */
	end.s_addr = ntohl(base.s_addr) - 1;
	end.s_addr += pow(2, 32 - tul);
	end.s_addr = htonl(end.s_addr);
	
	/* add all the ips in this cidr block (excluding .0 and .255) */
	for (ip = base;
	     ntohl(ip.s_addr) <= ntohl(end.s_addr);
	     ip.s_addr = htonl(ntohl(ip.s_addr) + 1))
	  {
	     tul = (ip.s_addr & 0xff000000) >> 24;
	     if (tul == 0 || tul == 255)
	       continue;
	     ntargs += add_target_ip(tl, (unsigned long)ip.s_addr);
	  }
     }
   else
     {
	/* an IP or a host name! */
	if (!inet_aton(targ, &ip))
	  {
	     struct hostent *hp;
	     int i;
	     
	     if (!(hp = gethostbyname(targ)))
	       {
		  fprintf(stderr, "Invalid host/ip: %s\n", targ);
		  return 0;
	       }
	     for (i = 0; hp->h_addr_list[i]; i++)
	       ntargs += add_target_ip(tl, *(unsigned long *)hp->h_addr_list[i]);
	  }
	else
	  ntargs += add_target_ip(tl, (unsigned long)ip.s_addr);
     }
   return ntargs;
}


/*
 * free a target that is no longer in use
 * /
static void
free_target(tl)
   targlist_t **tl;
{
   targlist_t *t = *tl;
   
   free(t);
   *tl = (targlist_t *)NULL;
}
 */


/*
 * add a target ip to the list of ips to attack
 */
static int
add_target_ip(tl, ip)
   targlist_t **tl;
   unsigned long ip;
{
   targlist_t *t, *tt = (targlist_t *)0;
   struct in_addr ipn;
   
   ipn.s_addr = ip;
   if (options.verbose >= 4)
     fprintf(stderr, "add_target_ip(tl, %s)\n", inet_ntoa(ipn));
   
   /* is it in the list already? */
   if (find_in_list(tl, &tt, ip))
     {
	if (options.verbose >= 2)
	  fprintf(stderr, "IP %s already in the target list!\n", inet_ntoa(ipn));
	return 0;
     }
   /* allocate storage for this IP */
   t = (targlist_t *)calloc(1, sizeof(targlist_t));
   if (!t)
     {
	fprintf(stderr, "Unable to allocate memory for a target list entry.\n");
	return 0;
     }
   t->ip.s_addr = ip;
   /* if tt is non-null then we have a nice indicator of where to link it. */
   if (tt)
     {
	t->next = tt->next;
	tt->next = t;
     }
   /* otherwise, the list must be empty */
   else
     {
	t->next = *tl;
	*tl = t;
     }
   return 1;
}


/*
 * find a target ip in the list..
 * 
 * if it is not found we return a pointer to the place before it should be
 * 
 */
static int
find_in_list(tl, tt, ip)
   targlist_t **tl, **tt;
   unsigned long ip;
{
   targlist_t *t;
   
   for (t = *tl; t; t = t->next)
     {
	/* is this it?? */
	if (t->ip.s_addr == ip)
	  return 1;
	
	/* are we there yet? */
	if (ntohl(t->ip.s_addr) < ntohl(ip))
	  {
	     /* end of list? */
	     if (!t->next)
	       break;
	     /* the next one is bigger? */
	     if (ntohl(t->next->ip.s_addr) > ntohl(ip))
	       break;
	  }
     }
   /* save the reference parameter and tell caller we didn't find it */
   *tt = t;
   return 0;
}
