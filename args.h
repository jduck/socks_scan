/*
 * args.h: header file for command line parameter parsing
 * 
 * written by Joshua J. Drake (jduck@EFNet, socks_scan@qoop.org)
 */

#ifndef __args_h_
#define __args_h_

#include "defs.h"
#include "targets.h"

/* options structure */
typedef struct
{
   unsigned int verbose;	/* verbosity level */
   unsigned int timeout;	/* tcp connection timeout */
   unsigned int connects;	/* number of simultaneous tests */
   struct sockaddr_in remote;	/* the remote host to try to get to */
   char *username; 		/* socks4 username */
   char *password;		/* socks5 password */
} opts_t;

/* external global options structure */
extern opts_t options;

/* prototypes */
extern int parse_args(int, char **, targlist_t **);

#endif
