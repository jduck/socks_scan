/*
 * socks5.h: SOCKS v5 proxy defines/prototypes
 * 
 * written by Joshua J. Drake (jduck@EFNet, socks_scan@qoop.org)
 */

#ifndef __socks5_h
#define __socks5_h

#include "socks.h"

/* defines for socks 5 stuff */
#define SOCKS5_VERSION 		5

/* auth types */
#define SOCKS5_AUTH_NONE 	0x00
#define SOCKS5_AUTH_GSSAPI 	0x01
#define SOCKS5_AUTH_PASSWD 	0x02
#define SOCKS5_AUTH_CHAP 	0x03
#define SOCKS5_AUTH_NOMATCH 	0xff

/* auth results */
#define SOCKS5_AUTH_OK 		0
#define SOCKS5_AUTH_FAIL 	-1

/* commands */
#define SOCKS5_CMD_CONNECT 	1
#define SOCKS5_CMD_BIND 	2
#define SOCKS5_CMD_UDP 		3
#define SOCKS5_CMD_PING 	0x80
#define SOCKS5_CMD_TRACER 	0x81
#define SOCKS5_CMD_ANY 		0xff

/* errors */
#define SOCKS5_ERR_NOERR 	0x00
#define SOCKS5_ERR_RESULT 	0x00
#define SOCKS5_ERR_FAIL 	0x01
#define SOCKS5_ERR_AUTHORIZE 	0x02
#define SOCKS5_ERR_NETUNREACH 	0x03
#define SOCKS5_ERR_HOSTUNREACH 	0x04
#define SOCKS5_ERR_CONNREF 	0x05
#define SOCKS5_ERR_TTLEXP 	0x06
#define SOCKS5_ERR_BADCMD 	0x07
#define SOCKS5_ERR_BADADDR 	0x08

/* flags */
#define SOCKS5_FLAG_NONAME 	0x01
#define SOCKS5_FLAG_VERBOSE 	0x02

/* address types */
#define SOCKS5_ATYP_IPV4ADDR 	0x01
#define SOCKS5_ATYP_HOSTNAME 	0x03
#define SOCKS5_ATYP_IPV6ADDR 	0x04

/* function prototypes */
	char	*socks5_error (int);
	int	socks5_connect (int, struct sockaddr_in, char *, char *, char *, unsigned int);
/* these are called by socks5_connect, but it blocks while using them */
	int	socks5_send_auth_req (int, char *, unsigned int);
	int	socks5_recv_auth_rep (int, char *, unsigned int);
	int	socks5_send_userpass_req (int, char *, char *, char *, unsigned int);
	int	socks5_recv_userpass_rep (int, char *, unsigned int);
	int	socks5_send_connect_req (int, struct sockaddr_in, char *, unsigned int);
	int	socks5_recv_connect_rep (int, char *, unsigned int);

#endif
