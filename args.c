/*
 * args.c: command line parameter parsing code
 * 
 * written by Joshua J. Drake (jduck@EFNet, socks_scan@qoop.org)
 */
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <pwd.h>

#include <netdb.h>

#include "targets.h"
#include "args.h"

#include "nsock_tcp.h"
#include "nsock_resolve.h"

/*
 * show the help! 
 */
void
show_usage(v0)
   char *v0;
{
   fprintf(stderr, 
	   "usage: %s [<options>] [<host/ip/cidr>] ...\n"
	   "\n"
	   "valid options:\n"
	   "  -f <file>           read targets from <file>\n"
	   "  -r <host>[:<port>]  change the remote host to connect to\n"
	   "  -s <slots>          set the # of parallel scans to <slots>\n"
	   "  -t <secs>           set connect timeout to <secs>\n"
	   "  -u <username>       set username reported to remote to <username>\n"
	   "  -v                  increase verbosity level once per use\n"
	   , v0);
}

/*
 * parse the command line paramters into the options structure
 */
int
parse_args(c, v, tlist)
   int c;
   char *v[];
   targlist_t **tlist;
{
   unsigned int ch;
   unsigned long tl, ntargs = 0;
   char *p;
   struct passwd *pw;
   struct sockaddr_in tin;
   
   /* initialize the options */
   memset(&options, 0, sizeof(options));
   options.timeout = DEFAULT_CONNECT_TIMEOUT;
   options.connects = DEFAULT_PARALLEL_CONNECTS;
   switch (nsock_resolve(nsock_tcp_host(DEFAULT_TARGET_HOST, DEFAULT_TARGET_PORT), &options.remote))
     {
      case NSOCK_R_SUCCESS:
	break;
      default:
	fprintf(stderr, "unable to resolve default target host/port\n");
	return -1;
     }
   if (!(pw = getpwuid(getuid())))
     {
	fprintf(stderr, "unable to figure out who i am\n");
	return -1;
     }
   options.username = strdup(pw->pw_name);

   /* check out the command line params */
   while ((ch = getopt(c, v, "f:r:s:t:u:v")) != -1)
     {
	switch (ch)
	  {
	   case 'f':
	     ntargs += load_targets_from_file(tlist, optarg);
	     break;
	   case 'r':
	     /* check out the hostname */
	     switch (nsock_resolve(optarg, &tin))
	       {
		case NSOCK_R_SUCCESS:
		  break;
		default:
		  fprintf(stderr, "-%c: unable to resolve target host/port: %s\n", ch, optarg);
		  return -1;
	       }
	     /* copy it into the active spot */
	     options.remote = tin;
	     break;
	   case 's':
	     tl = strtoul(optarg, &p, 0);
	     if (*p || p == optarg || tl < 1 || tl > 300)
	       {
		  fprintf(stderr, "-%c: invalid slot count value: %s\n", ch, optarg);
		  return -1;
	       }
	     options.connects = tl;
	     break;
	   case 't':
	     tl = strtoul(optarg, &p, 0);
	     if (*p || p == optarg || tl < 1 || tl > 600)
	       {
		  fprintf(stderr, "-%c: invalid timeout value: %s\n", ch, optarg);
		  return -1;
	       }
	     options.timeout = tl;
	     break;
	   case 'u':
	     if (options.username)
	       free(options.username);
	     options.username = strdup(optarg);
	     break;
	   case 'v':
	     options.verbose++;
	     break;
	   case '?':
	     show_usage(v[0]);
	     return -1;
	   default:
	     fprintf(stderr, "the -%c option is not implemented.\n", ch);
	     return -1;
	     /* not reached */
	  }
     }
   
   /* make already parsed adjustments */
   c -= optind;
   v += optind;
   
   /* parse the remainder of the command line arguments */
   if (c > 0)
     {
	int i;
	
	for (i = 0; i < c; i++)
	  ntargs += add_target(tlist, v[i]);
     }
   return ntargs;
}
