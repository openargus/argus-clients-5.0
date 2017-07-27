#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include "argus_util.h"
#include "argus_threads.h"
#include "rabootp.h"

static pthread_mutex_t __memlock = PTHREAD_MUTEX_INITIALIZER;

struct ArgusDhcpStruct *
ArgusDhcpStructAlloc(void)
{
   struct ArgusDhcpStruct *res;

   res = ArgusMallocAligned(sizeof(struct ArgusDhcpStruct), 64);
   if (res) {
      memset(res, 0, sizeof(struct ArgusDhcpStruct));
      res->refcount = 1;
      res->lock = ArgusMalloc(sizeof(*res->lock));
      if (res->lock == NULL) {
         ArgusFree(res);
         return NULL;
      }
      MUTEX_INIT(res->lock, NULL);
   }
   return res;
}

void
ArgusDhcpStructFreeReplies(void *v)
{
   struct ArgusDhcpStruct *a = v;
   struct ArgusDhcpV4LeaseOptsStruct *rep = &a->rep;

   while (rep) {
      if (rep->hostname)
         free(rep->hostname);
      if (rep->domainname)
         free(rep->domainname);
      rep = rep->next;
   }
}

void
ArgusDhcpStructFreeRequest(void *v)
{
   struct ArgusDhcpStruct *a = v;

   if (a->req.client_id_len > 8 && a->req.client_id.ptr)
      ArgusFree(a->req.client_id.ptr);
   if (a->req.requested_opts)
      ArgusFree(a->req.requested_opts);
   if (a->req.requested_hostname)
      free(a->req.requested_hostname);
}

void
ArgusDhcpStructFree(void *v)
{
   struct ArgusDhcpStruct *a = v;

   if (MUTEX_LOCK(&__memlock) == 0) {

#ifdef ARGUSDEBUG
      if (a->refcount == 0)
         abort();
#endif

      if (--(a->refcount) == 0) {
         ArgusDhcpStructFreeRequest(v);
         ArgusDhcpStructFreeReplies(v);
         if (a->sql_table_name)
            free(a->sql_table_name);
         MUTEX_DESTROY(a->lock);
         ArgusFree(a->lock);
         ArgusFree(a);
      }
      MUTEX_UNLOCK(&__memlock);
   }
}

void
ArgusDhcpStructUpRef(struct ArgusDhcpStruct *a)
{
   if (MUTEX_LOCK(&__memlock) == 0) {

#ifdef ARGUSDEBUG
      if (a->refcount == 255) {
         abort();
      }
#endif

      a->refcount++;
      MUTEX_UNLOCK(&__memlock);
   }
}