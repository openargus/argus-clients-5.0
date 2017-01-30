/*
 * Gargoyle Client Software. Tools to read, analyze and manage Argus data.
 * Copyright (c) 2000-2016 QoSient, LLC
 * All rights reserved.
 *
 * THE ACCOMPANYING PROGRAM IS PROPRIETARY SOFTWARE OF QoSIENT, LLC,
 * AND CANNOT BE USED, DISTRIBUTED, COPIED OR MODIFIED WITHOUT
 * EXPRESS PERMISSION OF QoSIENT, LLC.
 *
 * QOSIENT, LLC DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS
 * SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL QOSIENT, LLC BE LIABLE FOR ANY
 * SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER
 * IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
 * ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF
 * THIS SOFTWARE.
 */
 
/*
 * $Id: //depot/gargoyle/clients/examples/radhcp/rabootp.h#3 $
 * $DateTime: 2016/08/22 00:32:32 $
 * $Change: 3173 $
 */
 
/*
 *     rabootp.h  - support for parsing DHCP transactions from argus data
 *
 */

#ifndef _RABOOTP_H_
#define	_RABOOTP_H_

#include <sys/types.h>
#include <netinet/in.h>
#include "argus_config.h"
#include "argus_util.h"
#include "argus_parser.h"
#include "argus_debug.h"
#include "dhcp.h"

#ifdef ARGUSDEBUG
# define DEBUGLOG(lvl, fmt...) ArgusDebug(lvl, fmt)
#else
# define DEBUGLOG(lvl, fmt...)
#endif

/* message type missing from dhcp.h */
#define DHCPFORCERENEW 9           /* RFC 3203 */

static inline uint16_t
__type2mask(const uint8_t t)
{
	return (1 << t);
}

static inline uint8_t
__mask2type(uint16_t mask)
{
   uint8_t msgtype = 0;

   for (mask >>= 1; mask; msgtype++, mask >>= 1);
   return msgtype;
}

static inline void
__options_mask_set(uint64_t mask[], uint8_t opt)
{
   uint8_t idx = opt/64;
   uint8_t shift = opt % 64;

   mask[idx] |= (1ULL << shift);
}

static inline void
__options_mask_clr(uint64_t mask[], uint8_t opt)
{
   uint8_t idx = opt/64;
   uint8_t shift = opt % 64;

   mask[idx] &= ~(1ULL << shift);
}


static inline uint8_t
__options_mask_isset(uint64_t mask[], uint8_t opt)
{
   uint8_t idx = opt/64;
   uint8_t shift = opt % 64;

   if (mask[idx] & (1ULL << shift))
      return opt;

   return 0;
}

enum ArgusDhcpState {
   __INVALID__  = 0,
   INITREBOOT   = 1,
   REBOOTING    = 2,
   REQUESTING   = 3,
   BOUND        = 4,
   RENEWING     = 5,
   REBINDING    = 6,
   SELECTING    = 7,
   INIT         = 8,
};

/* either accepted lease or offer */
/* IP addresses are in network byte order */
struct ArgusDhcpV4LeaseOptsStruct {

   /* first cacheline */
   unsigned char shaddr[16];       /* server's L2 address */
   uint64_t options[4];            /* bitmask - 256 possible options */
   uint32_t leasetime;             /* option 51 */
   struct in_addr router;          /* option 3 first router */
   struct in_addr yiaddr;          /* yiaddr from non-options payload */
   struct in_addr ciaddr;          /* ciaddr from non-options payload */

   /* second cacheline */
   struct in_addr netmask;         /* option 1 */
   struct in_addr broadcast;       /* option 28 */
   struct in_addr timeserver[2];   /* option 42 first 2 timeservers */
   struct in_addr nameserver[2];   /* option 6 first 2 nameservers */
   char *hostname;                 /* option 12 */
   char *domainname;               /* option 15 */
   struct in_addr server_id;       /* option 54 */
   uint8_t router_count;           /* option 3 */
   uint8_t timeserver_count;       /* option 42 */
   uint8_t nameserver_count;       /* option 6 */
   uint8_t option_overload;        /* option 52 */
   struct in_addr siaddr;          /* siaddr from non-options payload */
   uint16_t mtu;                   /* option 26 */
   uint16_t pad0;                  /* PAD */
   struct ArgusDhcpV4LeaseOptsStruct *next;
};

/* IP addresses are in network byte order */
struct ArgusDhcpV4RequstOptsStruct {
   uint64_t options[4];            /* bitmask - 256 possible options */
   uint8_t *requested_opts;        /* option 55 */
   union {
      /* use bytes array if length <= 8 */
      uint8_t *ptr;
      uint8_t bytes[8];
   } client_id;                    /* option 61 */
   struct in_addr requested_addr;  /* option 50 */
   uint8_t requested_options_count;
   uint8_t client_id_len;
   /* uint8_t pad[8]; */           /* PAD */
};

/* chaddr + xid uniquely identifies host state */
/* IP addresses are in network byte order */
struct ArgusDhcpStruct {
   /* first x86_64 cacheline */
   unsigned char chaddr[16];       /* client L2 address */
   unsigned char shaddr[16];       /* accepted server's L2 address */
   union {                         /* accpeted server L3 address - 16 bytes */
      struct in_addr v4;
      struct in6_addr v6;
   } server_addr;
   uint32_t xid;                   /* transaction ID from dhcp packet */
   uint16_t msgtypemask;           /* mask of option-53 message types */
   uint8_t hlen;
   uint8_t refcount;

   unsigned short total_responses; /* how many replies received with this xid */
   unsigned short num_responders;  /* how many unique servers replied */
   unsigned short total_requests;  /* how many request packets with this
                                    * chaddr+xid
                                    */
   unsigned short total_unknownops;/* unknown opcodes received */

   /* second cacheline */
   struct ArgusDhcpV4RequstOptsStruct req;
   uint8_t pad0[4];
   enum ArgusDhcpState state;      /* 4 bytes on x86_64 with llvm & gcc */

   /* third + fourth cachelines */
   struct ArgusDhcpV4LeaseOptsStruct rep; /* This is a linked list of replies */
};

struct ArgusDhcpStruct *ArgusParseDhcpRecord (struct ArgusParserStruct *, struct ArgusRecordStruct *, struct ArgusDhcpStruct *);
void RabootpCleanup(void);

/*
 * Vendor magic cookie (v_magic) for RFC1048
 */
#define VM_RFC1048   { 99, 130, 83, 99 }

#endif
