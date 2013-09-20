/*
 * defs.h: default settings
 * 
 * written by Joshua J. Drake (jduck@EFNet, socks_scan@qoop.org)
 */

#ifndef __defs_h_
#define __defs_h_

/* a minute should be more than enough time to connect */
#define DEFAULT_CONNECT_TIMEOUT		60

/* 5 simultaneous connection attempts should be good.. */
#define DEFAULT_PARALLEL_CONNECTS 	5

/* make sure these are set to something that will connect */
#define DEFAULT_TARGET_HOST 	"198.108.130.5"
#define DEFAULT_TARGET_PORT	53

#endif
