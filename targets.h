/*
 * targets.h: header file for scanning targets
 * 
 * written by Joshua J. Drake <socks_scan@qoop.org>
 */

#ifndef __targets_h
#define __targets_h

#include <arpa/inet.h>


/* connection states */
#define SPSS_STARTED 		0x00000001

#define SPSS_4_CONNECTING 	0x00000010
#define SPSS_4_CONNECTED 	0x00000020
#define SPSS_4_REQ_SENT		0x00000040
#define SPSS_4_REP_RECVD 	0x00000080
#define SPSS_4_DONE 		0x00000100
#define SPSS_4_SUCCESSFUL 	0x00000200

#define SPSS_5_CONNECTING 	0x00010000
#define SPSS_5_CONNECTED 	0x00020000
#define SPSS_5_AUTH_REQ_SENT 	0x00040000
#define SPSS_5_AUTH_REP_RECVD 	0x00080000
#define SPSS_5_AUTH_NONE_OK 	0x00100000
#define SPSS_5_AUTH_PASS_OK 	0x00200000
#define SPSS_5_REQ_SENT 	0x00400000
#define SPSS_5_REP_RECVD 	0x00800000
#define SPSS_5_DONE 		0x01000000
#define SPSS_5_SUCCESSFUL 	0x02000000

#define SPSS_FINISHED 		0x80000000

/* data types */
typedef struct __target_stru
{
   struct __target_stru *next;
   struct in_addr ip;
   unsigned long state;
} targlist_t;


/* prototypes */
unsigned int load_targets_from_file(targlist_t **, char *);
int add_target(targlist_t **, char *);

#endif
