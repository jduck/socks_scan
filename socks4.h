/*
 * socks4.h: SOCKS v4 proxy defines and prototypes
 * 
 * written by Joshua J. Drake (jduck@EFNet, socks_scan@qoop.org)
 */

#ifndef __socks4_h
#define __socks4_h

#include <arpa/inet.h>

#include "socks.h"

/* the version # */
#define SOCKS4_VERSION	4

/* commands */
#define SOCKS_CONNECT   1
#define SOCKS_BIND      2

/* function prototypes */
	char	*socks4_error(int);
	int	socks4_connect(int, struct sockaddr_in, char *, char *, unsigned int);
/* these are called by socks4_connect, but it blocks while using them */
	int	socks4_send_connect_req(int, struct sockaddr_in, char *, char *, unsigned int);
	int	socks4_recv_connect_rep(int, char *, unsigned int);

#endif
