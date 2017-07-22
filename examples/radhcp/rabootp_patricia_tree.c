/*
 * Gargoyle Client Software. Tools to read, analyze and manage Argus data.
 * Copyright (c) 2017 QoSient, LLC
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
 * Helper functions for maintaining a patricia tree of IP addresses for
 * looking up DHCP lease information.  Each host (a.b.c.d/32) node in the
 * patricia tree has a list of all L-2 addresses (Ethernet, most likely)
 * that have leased that particular IP address.  Each L-2 address in turn
 * points to an Interval Tree describing the leases of the specified IP
 * address by endsystem with the current L-2 address.
 */

#include <syslog.h>
#include "argus_util.h"
#include "argus_client.h"
#include "argus_parser.h"
#include "argus_label.h"
#include "argus_filter.h" /* etheraddr_string */
#include "argus_debug.h"
#include "rabootp.h"
#include "rabootp_l2addr_list.h"
#include "rabootp_interval_tree.h"
#include "rabootp_patricia_tree.h"

extern struct ArgusParserStruct *ArgusParser;

int
RabootpPatriciaTreeUpdate(const struct ArgusDhcpStruct * const parsed,
                          struct ArgusDhcpStruct *cached,
                          struct ArgusParserStruct *parser)
{
   struct ArgusLabelerStruct *labeler = parser->ArgusLabeler;
   struct RaAddressStruct *ras;
   struct rabootp_l2addr_list_head *l2list;
   struct rabootp_l2addr_entry *l2entry;
   struct ArgusDhcpIntvlTree *intvltree;
   struct ArgusDhcpIntvlNode *node;
   int rv = 0;

   /* TODO: dig through the replies and use that chosen by the client (if known) */
   ras = RaProcessAddress(parser, labeler,
                          (unsigned int *)&parsed->rep.yiaddr, 32,
                          ARGUS_TYPE_IPV4, ARGUS_EXACT_MATCH);
   if (ras == NULL) {
      ArgusLog(LOG_WARNING, "%s: Unable to add address to P-tree\n", __func__);
      rv = -1;
      goto out;
   }

   if (ras->obj == NULL) {
      l2list = rabootp_l2addr_list_alloc();
      if (l2list == NULL) {
         ArgusLog(LOG_WARNING,
                  "%s: Unable to allocate L2 address list for P-tree\n",
                  __func__);
         rv = -1;
         goto out;
      }
      ras->obj = l2list;
   } else {
      l2list = ras->obj;
   }

   l2entry = rabootp_l2addr_list_search(l2list, cached->chaddr, cached->hlen);
   if (l2entry == NULL) {
      intvltree = ArgusDhcpIntvlTreeAlloc();
      if (intvltree == NULL) {
         ArgusLog(LOG_WARNING, "%s: Unable to allocate per-l2 interval tree\n",
                  __func__);
         rv = -1;
         goto out;
      }

      memset(intvltree, 0, sizeof(*intvltree));
      l2entry = rabootp_l2addr_list_insert(l2list, cached->chaddr, cached->hlen,
                                           intvltree);
   } else {
      intvltree = l2entry->datum;
   }
   if (l2entry == NULL) {
      rv = -1;
      goto out;
   }

   node = IntvlTreeFind(intvltree, &cached->last_bind);
   if (node == NULL) {
      ArgusDhcpIntvlTreeInsert(intvltree,
                               &cached->last_bind,
                               parsed->rep.leasetime,
                               cached);
   } else {
      /* can't update interval tree yet.  we already complain about this
       * elsewhere
       */
   }

out:
   return rv;
}


/* __minmax and __next adapted from BSD's sys/tree.h for non-recursive
 * traversal
 */

static
struct RaAddressStruct *
__minmax(struct RaAddressStruct *elm, int val)
{
   struct RaAddressStruct *tmp = elm;
   struct RaAddressStruct *parent = NULL;
   while (tmp) {
      parent = tmp;
      if (val < 0)
         tmp = tmp->l;
      else
         tmp = tmp->r;
   }
   return (parent);
}

static
struct RaAddressStruct *
__next(struct RaAddressStruct *elm)
{
   if (elm == NULL)
      return NULL;

   if (elm->r) {
      elm = elm->r;
      while (elm->l)
         elm = elm->l;
   } else {
      if (elm->p && elm == (elm->p)->l)
         elm = elm->p;
      else {
         while (elm->p && elm == (elm->p)->r)
            elm = elm->p;
         elm = elm->p;
      }
   }
   return (elm);
}

/* Caller must hold parser lock */
int
RabootpPatriciaTreeForeach(struct RaAddressStruct *node,
                           RabootpPatriciaTreeCallback cb,
                           void *arg)
{
   struct RaAddressStruct *tmp;
   int rv = 0;

   for (tmp = __minmax(node, -1); tmp && !rv; tmp = __next(tmp))
      rv = cb(tmp, arg);

   return rv;
}

static struct RaAddressStruct *
__find(const unsigned int * const yiaddr,
       struct ArgusParserStruct *parser)
{
   struct ArgusLabelerStruct *labeler;
   struct RaAddressStruct node;

   labeler = parser->ArgusLabeler;

   memset(&node, 0, sizeof(node));
   node.addr.addr[0] = *yiaddr;
   node.addr.masklen = 32;
   node.addr.mask[0] = 0xFFFFFFFF;

   return RaFindAddress(parser, labeler->ArgusAddrTree[AF_INET], &node,
                        ARGUS_EXACT_MATCH);
}

struct RaAddressStruct *
RabootpPatriciaTreeFind(const unsigned int * const yiaddr,
                        struct ArgusParserStruct *parser)
{
   return __find(yiaddr, parser ? parser : ArgusParser);
}

/* remove one lease from the patricia tree */
int
RabootpPatriciaTreeRemoveLease(const unsigned int * const yiaddr,
                               const unsigned char * const l2addr,
                               size_t l2len,
                               const struct timeval * const intlo,
                               struct ArgusParserStruct *parser)
{
   struct RaAddressStruct *ras;
   struct rabootp_l2addr_list_head *l2list;
   struct rabootp_l2addr_entry *l2entry;
   struct ArgusDhcpIntvlTree *intvltree;
   int rv = 0;

   if (parser == NULL)
      parser = ArgusParser;

   ras = __find(yiaddr, parser);
   if (ras == NULL) {
      rv = -1;
      goto out;
   }

   l2list = ras->obj;
   if (l2list == NULL) {
      rv = -1;
      goto out;
   }

   l2entry = rabootp_l2addr_list_search(l2list, l2addr, l2len);
   if (l2entry == NULL) {
      rv = -1;
      goto out;
   }

   rv = ArgusDhcpIntvlTreeRemove(l2entry->datum, intlo);

   if (ArgusDhcpIntvlTreeEmpty(l2entry->datum)) {
      ArgusDhcpIntvlTreeFree(l2entry->datum);
      l2entry->datum = NULL;

      if (rabootp_l2addr_list_remove(l2list, l2addr, l2len)) {
         ArgusFree(l2entry);
         if (rabootp_l2addr_list_empty(l2list)) {
            rabootp_l2addr_list_free(l2list);
            ras->obj = NULL;
         }
      }
   }

   DEBUGLOG(1, "%s: ArgusDhcpIntvlTreeRemove() returned %d\n", __func__, rv);

out:
   return rv;
}

#ifdef notdef

struct string {
   char *s;
   size_t len;
   size_t remain;
};

extern struct ArgusParserStruct *ArgusParser;
static int
__display_ipv4_cb(struct RaAddressStruct *ras, void *arg)
{
   struct string *string = arg;
   u_int addr;
   struct rabootp_l2addr_list_head *l2list;
   struct rabootp_l2addr_entry *l2entry;

   if (ras->addr.masklen != 32)
      return 0;

   memcpy(&addr, &ras->addr.addr[0], sizeof(addr));
   addr &= (0xFFFFFFFF << (32 - ras->addr.masklen));
   snprintf_append(string->s, &string->len, &string->remain, "%s\n",
                   intoa(addr));

   l2list = ras->obj;
   if (l2list == NULL)
      return 0;

   SLIST_FOREACH(l2entry, &l2list->head, list) {
      snprintf_append(string->s, &string->len, &string->remain, "   %s\n",
                      etheraddr_string(ArgusParser, l2entry->l2addr));
   }
   return 0;
}

ssize_t
RabootpPatriciaTreeDump(struct RaAddressStruct *ras, char *s, size_t slen)
{
   struct string string;
   struct RaAddressStruct *tmp;
   int rv = 0;

   string.s = s;
   string.len = 0;
   string.remain = slen;


   /*
    * It is significantly faster to call the inline function here instead of
    * passing it as a callback to the Foreach function.
    *
    * *** RabootpPatriciaTreeForeach(ras, __display_ipv4_cb, &string);
    *
    */

   for (tmp = __minmax(ras, -1); tmp && !rv; tmp = __next(tmp))
      rv = __display_ipv4_cb(tmp, &string);

   return (ssize_t)string.len;
}

#endif
