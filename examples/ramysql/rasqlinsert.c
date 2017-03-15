/*
 * Gargoyle Client Software. Tools to read, analyze and manage Argus data.
 * Copyright (c) 2000-2014 QoSient, LLC
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
 *
 *  rasqlinsert.c - this module handles the curses screen input and
 *                  output operations
 *
 *  Author: Carter Bullard carter@qosient.com
 */

/* 
 * $Id: //depot/gargoyle/clients/examples/ramysql/rasqlinsert.c#40 $
 * $DateTime: 2016/12/05 10:32:59 $
 * $Change: 3255 $
 */


#ifdef HAVE_CONFIG_H
#include "argus_config.h"
#endif

#include <argus_threads.h>
#include <time.h>

#define ARGUS_RECORD_MODIFIED   0x0100
#define ARGUS_RECORD_CLEARED    0x0200

#define ARGUS_SQL_INSERT        0x0100000
#define ARGUS_SQL_UPDATE        0x0200000
#define ARGUS_SQL_DELETE        0x0400000

#define ARGUS_SQL_STATUS        (ARGUS_SQL_INSERT | ARGUS_SQL_UPDATE | ARGUS_SQL_DELETE)

#if defined(CYGWIN)
#define USE_IPV6
#endif

#define RA_CURSES_MAIN
#include <rasqlinsert.h>

#if defined(ARGUS_THREADS)
pthread_attr_t RaTopAttr;
pthread_t RaMySQLThread = 0;
pthread_t RaMySQLSelectThread = 0;
pthread_t RaMySQLUpdateThread = 0;
pthread_t RaMySQLInsertThread = 0;
pthread_mutex_t RaMySQLlock;

void *ArgusMySQLInsertProcess (void *);
void *ArgusMySQLUpdateProcess (void *);
void *ArgusMySQLSelectProcess (void *);
#endif

#if defined(ARGUS_MYSQL)
int ArgusTotalInsertSQLStatements = 0;
int ArgusTotalUpdateSQLStatements = 0;
int ArgusTotalSelectSQLStatements = 0;
unsigned long long ArgusTotalCommitSQLStatements = 0ULL;


#include <netdb.h>
#include <sys/socket.h>

#include <mysql.h>

char *RaDatabase = NULL;
char **RaTables = NULL;

long long ArgusTotalSQLSearches = 0;
long long ArgusTotalSQLUpdates  = 0;
long long ArgusTotalSQLWrites = 0;
 
int ArgusSQLBulkInsertSize = 0;
int ArgusSQLMaxPacketSize = 0;
int ArgusSQLBulkBufferSize = 0;
int ArgusSQLBulkBufferIndex = 0;
int ArgusSQLBulkBufferCount = 0;
char *ArgusSQLBulkLastTable = NULL;
char *ArgusSQLBulkBuffer = NULL;
char *ArgusSQLVersion = NULL;
int MySQLVersionMajor = 0;
int MySQLVersionMinor = 0;
int MySQLVersionSub = 0;

extern int ArgusSOptionRecord;
int ArgusDeleteTable = 0;

int ArgusDropTable = 0;
int ArgusCreateTable = 0;
int ArgusAutoId = 0;

struct timeval ArgusLastRealTime     = {0, 0};
struct timeval ArgusLastTime         = {0, 0};
struct timeval ArgusThisTime         = {0, 0};
struct timeval ArgusCurrentTime      = {0, 0};

char ArgusSQLSaveTableNameBuf[1024];
struct tm ArgusSaveTableTmStruct;
time_t ArgusSaveTableSeconds = 0;

int ArgusCreateSQLSaveTable(char *, char *);
int ArgusScheduleSQLQuery (struct ArgusParserStruct *, struct ArgusAggregatorStruct *, struct ArgusRecordStruct *, char *, int);

void RaMySQLDeleteRecords(struct ArgusParserStruct *, struct ArgusRecordStruct *);

void RaSQLQueryNetworksTable (unsigned int, unsigned int, unsigned int);
void RaSQLQueryProbes (void);
void RaSQLQuerySecondsTable (unsigned int, unsigned int);

char *ArgusCreateSQLSaveTableName (struct ArgusParserStruct *, struct ArgusRecordStruct *, char *);
struct RaBinProcessStruct *ArgusNewRateBins (struct ArgusParserStruct *, struct ArgusRecordStruct *);

int RaInitialized = 0;
int RaSQLMcastMode = 0;

char *RaRoleString = NULL;
char *RaProbeString = NULL;
char *RaSQLCurrentTable = NULL;

char RaSQLSaveTable[MAXSTRLEN];

#define RA_MAXTABLES            0x100000

unsigned int RaTableFlags = 0;

char *RaTableValues[256];
char *RaTableExistsNames[RA_MAXTABLES];
char *RaTableCreateNames[RA_MAXTABLES];
char *RaTableCreateString[RA_MAXTABLES];
char *RaTableDeleteString[RA_MAXTABLES];

char *RaSource       = NULL;
char *RaArchive      = NULL;
char *RaLocalArchive = NULL;
char *RaFormat       = NULL;
char *RaTable        = NULL;
int   RaPeriod       = 1;
int   RaStatus       = 1;

int   RaSQLMaxSecs   = 0;
int   RaSQLUpdateDB  = 1;
int   RaSQLCacheDB   = 0;
int   RaSQLDBInserts = 0;
int   RaSQLDBUpdates = 0;
int   RaSQLDBDeletes = 1;
int   RaFirstManRec  = 1;

char ArgusArchiveBuf[MAXPATHNAMELEN];
char RaLocalArchiveBuf[MAXSTRLEN];

extern char *RaRemoteFilter;
extern char *RaLocalFilter;

extern char RaFilterSQLStatement[];

char *RaHost = NULL, *RaUser = NULL, *RaPass = NULL;
int RaPort = 0;

struct ArgusInput *ArgusInput = NULL;
void RaMySQLInit (void);

MYSQL_ROW row;
MYSQL *RaMySQL = NULL;

struct ArgusSQLQueryStruct {
   struct ArgusListObjectStruct *nxt;
   char *tbl, *sptr, *dptr;
};


#define RA_MAXSQLQUERY          3
char *RaTableQueryString[RA_MAXSQLQUERY] = {
   "SELECT id, name from NTAIS.Probes",
   "SELECT * from %s_%s_Seconds WHERE second >= %u and second <= %u",
   "SELECT filename from %s_%s_Filename WHERE id = %d",
};

#define RA_MAXMCASTSQLQUERY     3
char *RaMcastTableQueryString[RA_MAXMCASTSQLQUERY] = {
   "SELECT record from %s_CurrMcastGroups where groupaddr=\"\"",
   "SELECT record from %s_CurrMcastSender",
   "SELECT record from %s_CurrMcastMember",
};


#define RAMYSQL_NETWORKSTABLE_NUMBER	0
#define RAMYSQL_NETWORKSTABLE_START	1
#define RAMYSQL_NETWORKSTABLE_END	2

struct RaMySQLNetworksTable {
   struct ArgusQueueHeader qhdr;
   unsigned int number;
   unsigned int start;
   unsigned int last;
};
 
struct RaMySQLFileStruct {
   struct ArgusQueueHeader qhdr;
   unsigned int probe;
   unsigned int fileindex;
   char *filename;
   unsigned int ostart, ostop;
};

#define RAMYSQL_SECONDTABLE_PROBE	0
#define RAMYSQL_SECONDTABLE_SECOND	1
#define RAMYSQL_SECONDTABLE_FILEINDEX	2
#define RAMYSQL_SECONDTABLE_OSTART	3
#define RAMYSQL_SECONDTABLE_OSTOP 	4

struct RaMySQLSecondsTable {
   struct ArgusQueueHeader qhdr;
   unsigned int fileindex;
   char *filename;
   unsigned int probe;
   unsigned int second;
   unsigned int ostart, ostop;
};

#define RAMYSQL_PROBETABLE_PROBE	0
#define RAMYSQL_PROBETABLE_NAME		1

struct RaMySQLProbeTable {
   struct ArgusQueueHeader qhdr;
   unsigned int probe;
   char *name;
};
 

void RaMySQLInit (void);
static void *ArgusOutputProcess (void *);

#endif

int
main(int argc, char **argv)
{
   struct ArgusParserStruct *parser = NULL;
   int ArgusExitStatus, i, cc;
   pthread_attr_t attr;

   for (i = 0, cc = 0; i < argc; i++)
      cc += strlen(argv[i]);

   if (strchr (argv[0], '/'))
      argv[0] = strrchr(argv[0], '/') + 1;

   ArgusThreadsInit(&attr);

   if ((parser = ArgusNewParser(argv[0])) != NULL) {
      ArgusParser = parser;
      ArgusMainInit (parser, argc, argv);
      ArgusClientInit (parser);

#if defined(ARGUS_THREADS)
      sigset_t blocked_signals;

      sigfillset(&blocked_signals);
      sigdelset(&blocked_signals, SIGTERM);
      sigdelset(&blocked_signals, SIGINT);
      sigdelset(&blocked_signals, SIGWINCH);

      pthread_sigmask(SIG_BLOCK, &blocked_signals, NULL);

      if (parser->writeDbstr != NULL) {
         if (parser->readDbstr != NULL)
            free(parser->readDbstr);
         parser->readDbstr = NULL; //if writing we'll need to read the same db
      }

#if defined(ARGUS_MYSQL)
      RaMySQLInit();
      ArgusParseInit(parser, NULL);

      for (i = 0; i < MAX_PRINT_ALG_TYPES; i++) {
         if (parser->RaPrintAlgorithmList[i] != NULL) {
            parser->RaPrintAlgorithm = parser->RaPrintAlgorithmList[i];
            if (!strncmp(parser->RaPrintAlgorithm->field, "autoid", 6)) {
               ArgusAutoId = 1;
               break;
            }
         }
      }

      if (RaDatabase && RaTable)
         parser->RaTasksToDo = 1;

      {
         sigset_t blocked_signals;
         sigset_t sigs_to_catch;

         sigfillset(&blocked_signals);
         pthread_sigmask(SIG_BLOCK, &blocked_signals, NULL);

         if ((pthread_create(&RaMySQLInsertThread, NULL, ArgusMySQLInsertProcess, ArgusParser)) != 0)
            ArgusLog (LOG_ERR, "main() pthread_create error %s\n", strerror(errno));

         if ((pthread_create(&RaMySQLSelectThread, NULL, ArgusMySQLSelectProcess, ArgusParser)) != 0)
            ArgusLog (LOG_ERR, "main() pthread_create error %s\n", strerror(errno));

         if ((pthread_create(&RaMySQLUpdateThread, NULL, ArgusMySQLUpdateProcess, ArgusParser)) != 0)
            ArgusLog (LOG_ERR, "main() pthread_create error %s\n", strerror(errno));

         sigemptyset(&sigs_to_catch);
         sigaddset(&sigs_to_catch, SIGHUP);
         sigaddset(&sigs_to_catch, SIGTERM);
         sigaddset(&sigs_to_catch, SIGQUIT);
         sigaddset(&sigs_to_catch, SIGINT);
         pthread_sigmask(SIG_UNBLOCK, &sigs_to_catch, NULL);
      }
#endif

      if ((pthread_create(&RaCursesThread, NULL, ArgusOutputProcess, NULL)) != 0)
         ArgusLog (LOG_ERR, "ArgusOutputProcess() pthread_create error %s\n", strerror(errno));
 
      if ((pthread_create(&RaDataThread, NULL, ArgusProcessData, NULL)) != 0)
         ArgusLog (LOG_ERR, "main() pthread_create error %s\n", strerror(errno));

      pthread_join(RaDataThread, NULL);
      ArgusCloseDown = 1;

//    pthread_join(RaCursesThread, NULL);
      pthread_join(RaMySQLInsertThread, NULL);
      pthread_join(RaMySQLUpdateThread, NULL);
      pthread_join(RaMySQLSelectThread, NULL);

      mysql_close(RaMySQL);
      ArgusWindowClose();
#endif
   }

   ArgusExitStatus = RaCursesClose(parser, &attr);
   exit (ArgusExitStatus);
}

int
RaCursesClose(struct ArgusParserStruct *parser, pthread_attr_t *attr)
{
   struct ArgusInput *addr;
   int retn = 0;


#if defined(ARGUS_THREADS)
   if (parser->Sflag) {
      void *retn = NULL;

      if (parser->ArgusReliableConnection)
         pthread_attr_destroy(attr);

      while ((addr = (void *)ArgusPopQueue(parser->ArgusActiveHosts, ARGUS_LOCK)) != NULL) {
         if (addr->tid != (pthread_t) 0) {
            pthread_join(addr->tid, &retn);
         }
      }
   }

   if (parser->dns != (pthread_t) 0)
      pthread_join(parser->dns, NULL);
#endif

   retn = parser->ArgusExitStatus;

//   ArgusCloseParser(parser);
   return (retn);
}


int RaInitCurses (void);
void RaOutputModifyScreen (void);
void RaOutputHelpScreen (void);
void RaResizeScreen(void);
void RaUpdateHeaderWindow(WINDOW *);
void RaUpdateDebugWindow(WINDOW *);
void RaUpdateStatusWindow(WINDOW *);
void ArgusOutputProcessInit(void);
void ArgusOutputProcessClose(void);
void ArgusProcessSqlData(struct ArgusWindowStruct *);

int ArgusFetchWindowData(struct ArgusWindowStruct *);

static void *
ArgusOutputProcess (void *arg)
{
   const struct timespec ts = {0, 200000000};

   struct timeval ntvbuf, *ntvp = &ntvbuf;
   struct timeval tvbuf, *tvp = &tvbuf;

   gettimeofday(ntvp, NULL);
   ArgusOutputProcessInit();

   while (!ArgusCloseDown) {
      int cnt = 0;
      gettimeofday(tvp, NULL);

      if (MUTEX_LOCK(&RaCursesLock) == 0) {

         if ((cnt = ArgusWindowQueue->count) > 0) {
            int i, retn;

            for (i = 0; i < cnt; i++) {
               struct ArgusWindowStruct *ws = (struct ArgusWindowStruct *)ArgusPopQueue(ArgusWindowQueue, ARGUS_LOCK);

               if ((retn = ws->data(ws)) > 0) {
                  if (ws == RaDataWindowStruct) {

                     struct ArgusQueueStruct *queue = RaOutputProcess->queue;

//                   if (MUTEX_LOCK(&queue->lock) == 0) {
                        if (queue->status & RA_MODIFIED)
                           ArgusTouchScreen();
//                      MUTEX_UNLOCK(&queue->lock);
//                   }

                     if (RaWindowImmediate || ((tvp->tv_sec > ntvp->tv_sec) || ((tvp->tv_sec  == ntvp->tv_sec) &&
                                                                                (tvp->tv_usec >  ntvp->tv_usec)))) {
                        ArgusProcessSqlData(ws);
                        ntvp->tv_sec  = tvp->tv_sec  + RaCursesUpdateInterval.tv_sec;
                        ntvp->tv_usec = tvp->tv_usec + RaCursesUpdateInterval.tv_usec;
                        while (ntvp->tv_usec > 1000000) {
                           ntvp->tv_sec  += 1;
                           ntvp->tv_usec -= 1000000;
                        }
                        RaWindowImmediate = FALSE;
                     }

                     ArgusProcessSqlData(ws);
                  }
               }
               ArgusAddToQueue (ArgusWindowQueue, &ws->qhdr, ARGUS_LOCK);
            }
         }

         MUTEX_UNLOCK(&RaCursesLock);
      }
      nanosleep (&ts, NULL);
   }

   ArgusOutputProcessClose();

#if defined(ARGUS_THREADS)
   pthread_exit (NULL);
#else
   return (NULL);
#endif
}


void
ArgusProcessSqlData(struct ArgusWindowStruct *ws)
{
   WINDOW *win = ws->window;

   if (win == RaCurrentWindow->window) {
      struct ArgusQueueStruct *queue = RaOutputProcess->queue;

      if ((RaWindowModified == RA_MODIFIED) || ArgusAlwaysUpdate) {
         if (RaWindowStatus) {
            if (MUTEX_LOCK(&queue->lock) == 0) {
#if defined(ARGUS_MYSQL)
                struct ArgusQueueHeader *qhdr = queue->start;
                int i = 0;
                struct ArgusRecordStruct *ns;

                for (i = 0; qhdr && (i < queue->count); i++, qhdr = qhdr->nxt) {
                        ns = (struct ArgusRecordStruct *)qhdr;
                        if (ns && (ns->status & ARGUS_RECORD_MODIFIED)) {
                           ns->status &= ~ARGUS_RECORD_MODIFIED;
                           ArgusScheduleSQLQuery (ArgusParser,
                                                  ArgusParser->ArgusAggregator,
                                                  ns, RaSQLCurrentTable, ARGUS_STATUS);
                        }
                }
#endif
               MUTEX_UNLOCK(&queue->lock);
            }
         }

         RaWindowModified = 0;
         RaWindowImmediate = FALSE;
      }
   }
#ifdef ARGUSDEBUG
   ArgusDebug (7, "ArgusProcessSqlData(%p)\n", ws);
#endif
}


// Manage curses screen.

#if defined(ARGUS_CURSES)

void
RaResizeHandler (int sig)
{
   RaScreenResize = TRUE;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "RaResizeHandler(%d)\n", sig);
#endif
}

void
ArgusOutputProcessInit()
{
   struct ArgusDomainStruct *dom = NULL;
   struct ArgusWindowStruct *ws  = NULL;

   if ((ArgusDomainQueue = ArgusNewQueue()) == NULL)
      ArgusLog(LOG_ERR, "ArgusOutputProcessInit: RaNewQueue error %s", strerror(errno));

   if ((ArgusWindowQueue = ArgusNewQueue()) == NULL)
      ArgusLog(LOG_ERR, "ArgusOutputProcessInit: RaNewQueue error %s", strerror(errno));

   if ((ws = (struct ArgusWindowStruct *)ArgusCalloc(1, sizeof(*ws))) == NULL)
      ArgusLog(LOG_ERR, "ArgusOutputProcessInit: ArgusCalloc error %s", strerror(errno));

   RaHeaderWindowStruct = ws;
   ws->window = RaHeaderWindow;
   ws->desc = strdup("RaHeaderWindow");
   ws->data = ArgusFetchWindowData;
   MUTEX_INIT(&ws->lock, NULL);
   ArgusAddToQueue (ArgusWindowQueue, &ws->qhdr, ARGUS_LOCK);

   if ((ws = (struct ArgusWindowStruct *)ArgusCalloc(1, sizeof(*ws))) == NULL)
      ArgusLog(LOG_ERR, "ArgusOutputProcessInit: ArgusCalloc error %s", strerror(errno));

   RaStatusWindowStruct = ws;

   ws->window = RaStatusWindow;
   ws->desc = strdup("RaStatusWindow");
   ws->data = ArgusFetchWindowData;
   MUTEX_INIT(&ws->lock, NULL);
   ArgusAddToQueue (ArgusWindowQueue, &ws->qhdr, ARGUS_LOCK);

   if ((ws = (struct ArgusWindowStruct *)ArgusCalloc(1, sizeof(*ws))) == NULL)
      ArgusLog(LOG_ERR, "ArgusOutputProcessInit: ArgusCalloc error %s", strerror(errno));

   RaDebugWindowStruct  = ws;
   ws->window = RaDebugWindow;
   ws->desc = strdup("RaDebugWindow");
   ws->data = ArgusFetchWindowData;
   MUTEX_INIT(&ws->lock, NULL);
   ArgusAddToQueue (ArgusWindowQueue, &ws->qhdr, ARGUS_LOCK);

   if ((ws = (struct ArgusWindowStruct *)ArgusCalloc(1, sizeof(*ws))) == NULL)
      ArgusLog(LOG_ERR, "ArgusOutputProcessInit: ArgusCalloc error %s", strerror(errno));
 
   RaDataWindowStruct   = ws;
   ws->window = RaDisplayWindow;
   ws->desc = strdup("RaDisplayWindow");
   ws->data = ArgusFetchWindowData;
   MUTEX_INIT(&ws->lock, NULL);
   ArgusAddToQueue (ArgusWindowQueue, &ws->qhdr, ARGUS_LOCK);

   if ((dom = (struct ArgusDomainStruct *) ArgusCalloc(1, sizeof(*dom))) == NULL)
      ArgusLog (LOG_ERR, "ArgusOutputProcess() ArgusCalloc error %s\n", strerror(errno));

   dom->ws = RaDataWindowStruct;
   ArgusAddToQueue (ArgusDomainQueue, &dom->qhdr, ARGUS_LOCK);

   RaCurrentWindow = RaDataWindowStruct;
}


int
ArgusFetchWindowData(struct ArgusWindowStruct *ws)
{
   int retn = 1;
   return(retn);
}



void
ArgusOutputProcessClose()
{

#if defined(ARGUS_MYSQL)
   if (RaSQLUpdateDB && RaSQLCurrentTable) {
       struct ArgusQueueStruct *queue = RaOutputProcess->queue;
       struct ArgusQueueHeader *qhdr = queue->start;
       int i = 0;
       struct ArgusRecordStruct *ns;

       for (i = 0; qhdr && (i < queue->count); i++, qhdr = qhdr->nxt) {
               ns = (struct ArgusRecordStruct *)qhdr;
               if (ns && (ns->status & ARGUS_RECORD_MODIFIED)) {
                  ns->status &= ~ARGUS_RECORD_MODIFIED;
                  ArgusScheduleSQLQuery (ArgusParser,
                                         ArgusParser->ArgusAggregator,
                                         ns, RaSQLCurrentTable, ARGUS_STATUS);
               }
       }
   }
#endif

#if defined(ARGUS_THREADS)
   if (ArgusParser->RaCursesMode)
      pthread_join(RaCursesInputThread, NULL);
#endif
}

int 
RaInitCurses ()
{
   return (1);
}


#endif


void
ArgusTouchScreen(void)
{
   RaWindowModified  = RA_MODIFIED;
   RaWindowImmediate = TRUE;
}

/* ArgusUpdateScreen: calling thread should have already aquired
 * the RaOutputProcess->queue mutex.
 */
void
ArgusUpdateScreen(void)
{
   struct ArgusQueueStruct *queue;

   ArgusTouchScreen();

   if ((queue = RaOutputProcess->queue) != NULL) {
      struct ArgusQueueHeader *qhdr;
      struct ArgusRecordStruct *ns;
      int i;

      if (ArgusParser->ns)
         ArgusParser->ns->status |= ARGUS_RECORD_MODIFIED;

      for (i = 0, qhdr = queue->start;
           qhdr && (i < queue->count);
           i++, qhdr = qhdr->nxt) {
         ns = (struct ArgusRecordStruct *)qhdr;
         ns->status |= ARGUS_RECORD_MODIFIED;
      }
   }
#if defined(ARGUSDEBUG)
   ArgusDebug (1, "ArgusUpdateScreen() returning\n");
#endif
}


void
ArgusWindowClose(void)
{
   ArgusParser->RaCursesMode = 0;
#if defined(ARGUSDEBUG)
   ArgusDebug (1, "ArgusWindowClose () returning\n");
#endif
}

int
RaProcessSplitOptions(struct ArgusParserStruct *parser, char *str, int len, struct ArgusRecordStruct *ns)
{
   char resultbuf[MAXSTRLEN], tmpbuf[MAXSTRLEN];
   char *ptr = NULL, *tptr = str;
   int retn = 0, i, x;

   bzero (resultbuf, len);

   while ((ptr = strchr (tptr, '$')) != NULL) {
      *ptr++ = '\0';
      sprintf (&resultbuf[strlen(resultbuf)], "%s", tptr);

      for (i = 0, x = 0; x < MAX_PRINT_ALG_TYPES; x++) {
         if (!strncmp (RaPrintAlgorithmTable[x].field, ptr, strlen(RaPrintAlgorithmTable[x].field))) {
            bzero (tmpbuf, MAXSTRLEN);
            RaPrintAlgorithmTable[x].print(parser, tmpbuf, ns, RaPrintAlgorithmTable[x].length);

            while (isspace((int)tmpbuf[strlen(tmpbuf) - 1]))
               tmpbuf[strlen(tmpbuf) - 1] = '\0';

            while (isspace((int)tmpbuf[i])) i++;
            sprintf (&resultbuf[strlen(resultbuf)], "%s", &tmpbuf[i]);

            ptr += strlen(RaPrintAlgorithmTable[x].field);
            while (*ptr && (*ptr != '$'))
               bcopy (ptr++, &resultbuf[strlen(resultbuf)], 1);
            break;
         }
      }

      tptr = ptr;
      retn++;
   }

   if (retn) {
      bzero (str, len);
      bcopy (resultbuf, str, strlen(resultbuf));
   }

#ifdef ARGUSDEBUG
   ArgusDebug (5, "RaProcessSplitOptions(%s, %d, 0x%x): returns %d", str, len, ns, retn);
#endif

   return (retn);
}


#if defined(ARGUS_MYSQL)

void
RaSQLQueryProbes ()
{
   struct RaMySQLProbeTable *sqry = NULL;
   char buf[2048], sbuf[2048];
   MYSQL_RES *mysqlRes;
   char *endptr;
   int retn, x;

   sprintf (buf, "%s", RaTableQueryString[0]);
#ifdef ARGUSDEBUG
   ArgusDebug (2, "RaSQLQueryProbes: SQL Query %s\n", buf);
#endif

   if (MUTEX_LOCK(&RaMySQLlock) == 0) {
   if ((retn = mysql_real_query(RaMySQL, buf, strlen(buf))) != 0)
      ArgusLog(LOG_INFO, "RaSQLQueryProbes: mysql_real_query error %s", mysql_error(RaMySQL));

   else {
      if ((mysqlRes = mysql_store_result(RaMySQL)) != NULL) {
         if ((retn = mysql_num_fields(mysqlRes)) > 0) {
            while ((row = mysql_fetch_row(mysqlRes))) {
               unsigned long *lengths;
    
               lengths = mysql_fetch_lengths(mysqlRes);
               bzero(sbuf, sizeof(sbuf));

               if ((sqry = (void *) ArgusCalloc (1, sizeof(*sqry))) == NULL)
                  ArgusLog(LOG_ERR, "ArgusCalloc error %s", strerror(errno));

               for (x = 0; x < retn; x++) {
                  snprintf(sbuf, 2048, "%.*s", (int) lengths[x], row[x] ? row[x] : "NULL");
                  switch (x) {
                     case RAMYSQL_PROBETABLE_PROBE:
                        sqry->probe = strtol(sbuf, &endptr, 10);
                        if (sbuf == endptr)
                           ArgusLog(LOG_ERR, "mysql database error: second returned %s", sbuf);
                        break;

                     case RAMYSQL_PROBETABLE_NAME:
                        sqry->name = strdup(sbuf);
                        break;
                  }
               }
               ArgusAddToQueue (ArgusProbeQueue, &sqry->qhdr, ARGUS_LOCK);
            }
         }
         mysql_free_result(mysqlRes);
      }
   }
   MUTEX_UNLOCK(&RaMySQLlock);
   }
}

void
RaSQLQuerySecondsTable (unsigned int start, unsigned int stop)
{
   struct RaMySQLSecondsTable *sqry = NULL;
   char buf[2048], sbuf[2048];
   MYSQL_RES *mysqlRes;
   char *endptr, *str;
   int retn, x;


   if (RaRoleString) {
      str = "SELECT * from %s_Seconds WHERE second >= %u and second <= %u",
      sprintf (buf, str, RaRoleString, start, stop);
   } else {
      str = "SELECT * from Seconds WHERE second >= %u and second <= %u",
      sprintf (buf, str, start, stop);
   }

#ifdef ARGUSDEBUG
   ArgusDebug (2, "RaSQLQuerySecondsTable: SQL Query %s\n", buf);
#endif

   if (MUTEX_LOCK(&RaMySQLlock) == 0) {
      if ((retn = mysql_real_query(RaMySQL, buf, strlen(buf))) != 0)
         ArgusLog(LOG_INFO, "RaSQLQuerySecondsTable: mysql_real_query error %s", mysql_error(RaMySQL));

      else {
         if ((mysqlRes = mysql_store_result(RaMySQL)) != NULL) {
            if ((retn = mysql_num_fields(mysqlRes)) > 0) {
               while ((row = mysql_fetch_row(mysqlRes))) {
                  unsigned long *lengths;
       
                  lengths = mysql_fetch_lengths(mysqlRes);
                  bzero(sbuf, sizeof(sbuf));

                  if ((sqry = (void *) ArgusCalloc (1, sizeof(*sqry))) == NULL)
                     ArgusLog(LOG_ERR, "ArgusCalloc error %s", strerror(errno));

                  for (x = 0; x < retn; x++) {
                     int y = x;
                     snprintf(sbuf, 2048, "%.*s ", (int) lengths[x], row[x] ? row[x] : "NULL");
                     if (!(RaRoleString)) 
                        y++;
                     
                     switch (y) {
                        case RAMYSQL_SECONDTABLE_PROBE:
                           sqry->probe = strtol(sbuf, &endptr, 10);
                           if (sbuf == endptr)
                              ArgusLog(LOG_ERR, "mysql database error: second returned %s", sbuf);
                           break;

                        case RAMYSQL_SECONDTABLE_SECOND:
                           sqry->second = strtol(sbuf, &endptr, 10);
                           if (sbuf == endptr)
                              ArgusLog(LOG_ERR, "mysql database error: second returned %s", sbuf);
                           break;

                        case RAMYSQL_SECONDTABLE_FILEINDEX:
                           sqry->fileindex = strtol(sbuf, &endptr, 10);
                           if (sbuf == endptr)
                              ArgusLog(LOG_ERR, "mysql database error: second returned %s", sbuf);
                           break;

                        case RAMYSQL_SECONDTABLE_OSTART:
                           sqry->ostart = strtol(sbuf, &endptr, 10);
                           if (sbuf == endptr)
                              ArgusLog(LOG_ERR, "mysql database error: second returned %s", sbuf);
                           break;

                        case RAMYSQL_SECONDTABLE_OSTOP:
                           sqry->ostop = strtol(sbuf, &endptr, 10);
                           if (sbuf == endptr)
                              ArgusLog(LOG_ERR, "mysql database error: second returned %s", sbuf);
                           break;
                     }
                  }

                  ArgusAddToQueue (ArgusModelerQueue, &sqry->qhdr, ARGUS_LOCK);
               }
            }

            mysql_free_result(mysqlRes);
         }
      }
      MUTEX_UNLOCK(&RaMySQLlock);
   }
}


/*
   Mysql URL that we will respond to is:
      mysql://[username[:password]@]hostname[:port]/database/tablename
*/

/*
   ArgusProcessSQLQueryList
      As long as we don't have any errors, process the list.
      If there are errors, return with the error code, such as
      CR_SERVER_GONE_ERROR, or CR_SERVER_LOST.  The calling routine
      will decide what to do.
*/


#if defined(ARGUS_THREADS)

int ArgusProcessSQLUpdateQueryList(struct ArgusParserStruct *);
int ArgusProcessSQLSelectQueryList(struct ArgusParserStruct *);
int ArgusProcessSQLInsertQueryList(struct ArgusParserStruct *);

int ArgusProcessSQLQueryList(struct ArgusParserStruct *, struct ArgusListStruct *);


int
ArgusProcessSQLQueryList(struct ArgusParserStruct *parser, struct ArgusListStruct *ArgusSQLQueryList)
{
   int retn = 0;
   int trans_retn;
   struct ArgusSQLQueryStruct *sqry = NULL;
   char *sptr = NULL;
   int slen = 0;

   if (!ArgusSQLQueryList)
       return retn;

   if (MUTEX_LOCK(&ArgusSQLQueryList->lock) == 0) {
      sqry = (void *) ArgusPopFrontList(ArgusSQLQueryList, ARGUS_NOLOCK);
      MUTEX_UNLOCK(&ArgusSQLQueryList->lock);
   }

   if (!sqry)
      return retn;

   if (MUTEX_LOCK(&RaMySQLlock) == 0) {

      trans_retn = retn = mysql_real_query(RaMySQL, "START TRANSACTION", 17);
      if (retn)
          ArgusLog(LOG_INFO, "%s: failed to start sql transaction", __func__);

      while (!retn && sqry) {
            if ((sptr = sqry->sptr) != NULL) {
               slen = strlen(sptr);
#if defined(ARGUSDEBUG)
               if (sqry->dptr != NULL)
                  ArgusDebug (3, "ArgusSQLQuery (%s)\n", sqry->dptr);
               else
                  ArgusDebug (3, "ArgusSQLQuery (%s)\n", sqry->sptr);
#endif
               switch (*sptr) {
                  case 'S':  {
#ifdef ARGUSDEBUG
                     ArgusDebug (3, "ArgusProcessSQLQueryList: Select query\n");
#endif
                     ArgusTotalSelectSQLStatements++;
                     break;
                  }

                  case 'U':  {
                        if ((retn = mysql_real_query(RaMySQL, sptr, slen)) != 0) {
                           ArgusLog(LOG_INFO, "ArgusProcessSQLQueryList(Update): %s mysql_real_query error %s", sqry->dptr, mysql_error(RaMySQL));
                        } else {
                           ArgusTotalSQLWrites += slen;
                           ArgusTotalSQLUpdates++;
                        }
                        ArgusTotalUpdateSQLStatements++;

                     break;
                  }

                  case 'I':  {
                        if ((retn = mysql_real_query(RaMySQL, sptr, slen)) != 0) {
                           ArgusLog(LOG_INFO, "ArgusProcessSQLQueryList(Insert): %s mysql_real_query error %s", sqry->dptr, mysql_error(RaMySQL));
                        } else {
                           ArgusTotalSQLWrites += slen;
                           ArgusTotalSQLUpdates++;
                        }
                        ArgusTotalInsertSQLStatements++;

                     break;
                  }
               }

               if (sqry->sptr != NULL)
                  free(sqry->sptr);
               if (sqry->dptr != NULL)
                  free(sqry->dptr);
               if (sqry->tbl != NULL)
                  free(sqry->tbl);
               ArgusFree(sqry);
            }

         if (MUTEX_LOCK(&ArgusSQLQueryList->lock) == 0) {
            sqry = (void *) ArgusPopFrontList(ArgusSQLQueryList, ARGUS_NOLOCK);
            MUTEX_UNLOCK(&ArgusSQLQueryList->lock);
         }
      }

      if (!trans_retn) {
         retn = mysql_real_query(RaMySQL, "COMMIT", 6);
         ArgusTotalCommitSQLStatements++;
         if (retn)
            ArgusLog(LOG_INFO, "%s: failed to commit sql transaction", __func__);
      }

      MUTEX_UNLOCK(&RaMySQLlock);
      }

   return (retn);
}


void *
ArgusMySQLInsertProcess (void *arg)
{
   struct ArgusParserStruct *parser = (struct ArgusParserStruct *) arg;
   sigset_t blocked_signals;

   sigfillset(&blocked_signals);
   pthread_sigmask(SIG_BLOCK, &blocked_signals, NULL);

#ifdef ARGUSDEBUG
   ArgusDebug (2, "ArgusMySQLInsertProcess() starting");
#endif

   while (!(ArgusCloseDown)) {
      if ((ArgusSQLInsertQueryList != NULL) && (ArgusSQLInsertQueryList->count > 0))
         ArgusProcessSQLQueryList(parser, ArgusSQLInsertQueryList);

      else {
         struct timespec tsbuf, *ts = &tsbuf;

         if (ArgusSQLInsertQueryList) {
            struct timeval tvp;

            gettimeofday (&tvp, 0L);
            ts->tv_sec   = 1 + tvp.tv_sec;
            ts->tv_nsec  = tvp.tv_usec * 1000;
            if (ts->tv_nsec > 1000000000) {
               ts->tv_sec++;
               ts->tv_nsec -= 1000000000;
            }
            MUTEX_LOCK(&ArgusSQLInsertQueryList->lock);
            pthread_cond_timedwait(&ArgusSQLInsertQueryList->cond, &ArgusSQLInsertQueryList->lock, ts);
            MUTEX_UNLOCK(&ArgusSQLInsertQueryList->lock);

         } else {
            ts->tv_sec  = parser->RaClientTimeout.tv_sec;
            ts->tv_nsec = parser->RaClientTimeout.tv_usec * 1000;
            nanosleep(ts, NULL);
         }
      }

      if (ArgusSQLBulkBufferIndex > 0) {
         int retn;

#ifdef ARGUSDEBUG
         ArgusDebug (3, "ArgusMySQLInsertProcess: residual buffer Count %d SQL Query len %d\n", ArgusSQLBulkBufferCount, ArgusSQLBulkBufferIndex);
#endif
         if (MUTEX_LOCK(&RaMySQLlock) == 0) {
            if ((retn = mysql_real_query(RaMySQL, ArgusSQLBulkBuffer, ArgusSQLBulkBufferIndex)) != 0) {
               ArgusLog(LOG_INFO, "ArgusMySQLInsertProcess: mysql_real_query error %s", mysql_error(RaMySQL));
            } else {
               ArgusTotalSQLWrites += ArgusSQLBulkBufferIndex;
            }

            ArgusSQLBulkBufferIndex = 0;
            ArgusSQLBulkBufferCount = 0;
            MUTEX_UNLOCK(&RaMySQLlock);
         }
      }
   }

   pthread_join(RaCursesThread, NULL);

   if ((ArgusSQLInsertQueryList != NULL) && (ArgusSQLInsertQueryList->count > 0))
      ArgusProcessSQLQueryList(parser, ArgusSQLInsertQueryList);

   if (RaSQLUpdateDB) {
      if (ArgusSQLBulkBufferIndex > 0) {
         int retn;

#ifdef ARGUSDEBUG
         ArgusDebug (3, "ArgusMySQLInsertProcess: residual buffer Count %d SQL Query len %d\n", ArgusSQLBulkBufferCount, ArgusSQLBulkBufferIndex);
#endif
         if (MUTEX_LOCK(&RaMySQLlock) == 0) {
            if ((retn = mysql_real_query(RaMySQL, ArgusSQLBulkBuffer, ArgusSQLBulkBufferIndex)) != 0) {
               ArgusLog(LOG_INFO, "ArgusMySQLInsertProcess(Residual): mysql_real_query error %s", mysql_error(RaMySQL));
            } else {
               ArgusTotalSQLWrites += ArgusSQLBulkBufferIndex;
            }

            ArgusSQLBulkBufferIndex = 0;
            ArgusSQLBulkBufferCount = 0;
            MUTEX_UNLOCK(&RaMySQLlock);
         }
      }
   }

   if (RaSQLUpdateDB) {
         int i, retn;
         char *str = NULL;

      if (ArgusDeleteTable) {
         for (i = 0; i < RA_MAXTABLES; i++) {
            if ((str = RaTableDeleteString[i]) != NULL) {
#ifdef ARGUSDEBUG
               ArgusDebug (2, "deleting table %s\n", str);
#endif
               if (MUTEX_LOCK(&RaMySQLlock) == 0) {
                  if ((retn = mysql_real_query(RaMySQL, str, strlen(str))) != 0)
                     ArgusLog(LOG_INFO, "ArgusMySQLInsertProcess(Update): mysql_real_query error %s", mysql_error(RaMySQL));
                  MUTEX_UNLOCK(&RaMySQLlock);
               }
            }
         }
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (2, "ArgusMySQLInsertProcess() done!");
#endif

#if defined(ARGUS_THREADS)
   pthread_exit (NULL);
#else
   return (NULL);
#endif
}



void *
ArgusMySQLSelectProcess (void *arg)
{
   struct ArgusParserStruct *parser = (struct ArgusParserStruct *) arg;
   struct timespec tsbuf, *ts = &tsbuf;
   sigset_t blocked_signals;

   sigfillset(&blocked_signals);
   pthread_sigmask(SIG_BLOCK, &blocked_signals, NULL);

   ts->tv_sec  = parser->RaClientTimeout.tv_sec;
   ts->tv_nsec = parser->RaClientTimeout.tv_usec * 1000;

#ifdef ARGUSDEBUG
   ArgusDebug (2, "ArgusMySQLSelectProcess() starting");
#endif

   while (!(ArgusCloseDown)) {
      if ((ArgusSQLSelectQueryList != NULL) && (ArgusSQLSelectQueryList->count > 0))
         ArgusProcessSQLQueryList(parser, ArgusSQLSelectQueryList);
      else {
         struct timespec tsbuf, *ts = &tsbuf;

         if (ArgusSQLSelectQueryList) {
            struct timeval tvp;

            gettimeofday (&tvp, 0L);
            ts->tv_sec   = parser->RaClientTimeout.tv_sec  + tvp.tv_sec;
            ts->tv_nsec  = (parser->RaClientTimeout.tv_usec + tvp.tv_usec) * 1000;
            if (ts->tv_nsec > 1000000000) {
               ts->tv_sec++;
               ts->tv_nsec -= 1000000000;
            }
            MUTEX_LOCK(&ArgusSQLSelectQueryList->lock);
            pthread_cond_timedwait(&ArgusSQLSelectQueryList->cond, &ArgusSQLSelectQueryList->lock, ts);
            MUTEX_UNLOCK(&ArgusSQLSelectQueryList->lock);

         } else {
            ts->tv_sec  = parser->RaClientTimeout.tv_sec;
            ts->tv_nsec = parser->RaClientTimeout.tv_usec * 1000;
            nanosleep(ts, NULL);
         }
      }
   }

   pthread_join(RaCursesThread, NULL);

   if ((ArgusSQLSelectQueryList != NULL) && (ArgusSQLSelectQueryList->count > 0))
      ArgusProcessSQLQueryList(parser, ArgusSQLSelectQueryList);

   if (RaSQLUpdateDB) {
         int i, retn;
         char *str = NULL;

      if (ArgusDeleteTable) {
         for (i = 0; i < RA_MAXTABLES; i++) {
            if ((str = RaTableDeleteString[i]) != NULL) {
#ifdef ARGUSDEBUG
               ArgusDebug (2, "deleting table %s\n", str);
#endif
               if (MUTEX_LOCK(&RaMySQLlock) == 0) {
                  if ((retn = mysql_real_query(RaMySQL, str, strlen(str))) != 0)
                     ArgusLog(LOG_INFO, "ArgusMySQLSelectProcess: mysql_real_query error %s", mysql_error(RaMySQL));
                  MUTEX_UNLOCK(&RaMySQLlock);
               }
            }
         }
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (2, "ArgusMySQLSelectProcess() done!");
#endif

#if defined(ARGUS_THREADS)
   pthread_exit (NULL);
#else
   return (NULL);
#endif
}



void *
ArgusMySQLUpdateProcess (void *arg)
{
   struct ArgusParserStruct *parser = (struct ArgusParserStruct *) arg;
   struct timespec tsbuf, *ts = &tsbuf;
   sigset_t blocked_signals;

   sigfillset(&blocked_signals);
   pthread_sigmask(SIG_BLOCK, &blocked_signals, NULL);

   ts->tv_sec  = parser->RaClientTimeout.tv_sec;
   ts->tv_nsec = parser->RaClientTimeout.tv_usec * 1000;

#ifdef ARGUSDEBUG
   ArgusDebug (2, "ArgusMySQLUpdateProcess() starting");
#endif

   while (!(ArgusCloseDown)) {
      if ((ArgusSQLUpdateQueryList != NULL) && (ArgusSQLUpdateQueryList->count > 0))
         ArgusProcessSQLQueryList(parser, ArgusSQLUpdateQueryList);
      else {
         struct timespec tsbuf, *ts = &tsbuf;

         if (ArgusSQLUpdateQueryList) {
            struct timeval tvp;

            gettimeofday (&tvp, 0L);
            ts->tv_sec   = parser->RaClientTimeout.tv_sec  + tvp.tv_sec;
            ts->tv_nsec  = (parser->RaClientTimeout.tv_usec + tvp.tv_usec) * 1000;
            if (ts->tv_nsec > 1000000000) {
               ts->tv_sec++;
               ts->tv_nsec -= 1000000000;
            }
            MUTEX_LOCK(&ArgusSQLUpdateQueryList->lock);
            pthread_cond_timedwait(&ArgusSQLUpdateQueryList->cond, &ArgusSQLUpdateQueryList->lock, ts);
            MUTEX_UNLOCK(&ArgusSQLUpdateQueryList->lock);

         } else {
            ts->tv_sec  = parser->RaClientTimeout.tv_sec;
            ts->tv_nsec = parser->RaClientTimeout.tv_usec * 1000;
            nanosleep(ts, NULL);
         }
      }
   }

   pthread_join(RaCursesThread, NULL);

   if ((ArgusSQLUpdateQueryList != NULL) && (ArgusSQLUpdateQueryList->count > 0))
      ArgusProcessSQLQueryList(parser, ArgusSQLUpdateQueryList);

   if (RaSQLUpdateDB) {
         int i, retn;
         char *str = NULL;

      if (ArgusDeleteTable) {
         for (i = 0; i < RA_MAXTABLES; i++) {
            if ((str = RaTableDeleteString[i]) != NULL) {
#ifdef ARGUSDEBUG
               ArgusDebug (2, "deleting table %s\n", str);
#endif
               if (MUTEX_LOCK(&RaMySQLlock) == 0) {
                  if ((retn = mysql_real_query(RaMySQL, str, strlen(str))) != 0)
                     ArgusLog(LOG_INFO, "ArgusMySQLUpdateProcess: mysql_real_query error %s", mysql_error(RaMySQL));
                  MUTEX_UNLOCK(&RaMySQLlock);
               }
            }
         }
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (2, "ArgusMySQLUpdateProcess() done!");
#endif

#if defined(ARGUS_THREADS)
   pthread_exit (NULL);
#else
   return (NULL);
#endif
}

#endif


void
RaMySQLInit ()
{
   my_bool reconnectbuf = 1, *reconnect = &reconnectbuf;
   char *sptr = NULL, *ptr;
   char userbuf[1024], sbuf[1024], db[1024], *dbptr = NULL;
   MYSQL_RES *mysqlRes;
   int retn = 0, x;

   bzero((char *)RaTableExistsNames,  sizeof(RaTableExistsNames));
   bzero((char *)RaTableCreateNames,  sizeof(RaTableCreateNames));
   bzero((char *)RaTableCreateString, sizeof(RaTableCreateString));
   bzero((char *)RaTableDeleteString, sizeof(RaTableDeleteString));

   if (ArgusParser->MySQLDBEngine == NULL)
      ArgusParser->MySQLDBEngine = strdup("MyISAM");

   if ((RaUser == NULL) && (ArgusParser->dbuserstr != NULL)) {
      bzero(userbuf, sizeof(userbuf));
      strncpy (userbuf, ArgusParser->dbuserstr, sizeof(userbuf));
      if ((sptr = strchr (userbuf, ':')) != NULL) {
         *sptr++ = '\0';
         RaPass = strdup(sptr);
      }
      RaUser = strdup(userbuf);
   }

   if ((RaPass == NULL) && (ArgusParser->dbpassstr != NULL))
      RaPass = ArgusParser->dbpassstr;

   if (RaDatabase == NULL) {
      if (ArgusParser->writeDbstr != NULL)
         RaDatabase = strdup(ArgusParser->writeDbstr);

      else if (ArgusParser->readDbstr != NULL)
         RaDatabase = strdup(ArgusParser->readDbstr);

      if (RaDatabase != NULL)
         if (!(strncmp("mysql:", RaDatabase, 6))) {
            char *tmp = RaDatabase;
            RaDatabase = strdup(&RaDatabase[6]);
            free(tmp);
         }
   }

   if (RaDatabase == NULL) {
      ArgusLog(LOG_ERR, "must specify database"); 

   } else {
      sprintf(db, "%s", RaDatabase);
      dbptr = db;
/*
      //[[username[:password]@]hostname[:port]]/database/tablename
*/

      if (!(strncmp ("//", dbptr, 2))) {
         char *rhost = NULL, *ruser = NULL, *rpass = NULL;
         if ((strncmp ("///", dbptr, 3))) {
            dbptr = &dbptr[2];
            rhost = dbptr;
            if ((ptr = strchr (dbptr, '/')) != NULL) {
               *ptr++ = '\0';
               dbptr = ptr;

               if ((ptr = strchr (rhost, '@')) != NULL) {
                  ruser = rhost;
                  *ptr++ = '\0';
                  rhost = ptr;
                  if ((ptr = strchr (ruser, ':')) != NULL) {
                     *ptr++ = '\0';
                     rpass = ptr;
                  } else {
                     rpass = NULL;
                  }
               }

               if ((ptr = strchr (rhost, ':')) != NULL) {
                  *ptr++ = '\0';
                  RaPort = atoi(ptr);
               }
            } else
               dbptr = NULL;

         } else {
            dbptr = &dbptr[3];
         }

         if (ruser != NULL) {
            if (RaUser != NULL) free(RaUser);
            RaUser = strdup(ruser);
         }
         if (rpass != NULL) {
            if (RaPass != NULL) free(RaPass);
            RaPass = strdup(rpass);
         }
         if (rhost != NULL) {
            if (RaHost != NULL) free(RaHost);
            RaHost = strdup(rhost);
         }
         free(RaDatabase);
         RaDatabase = strdup(dbptr);
      }
   }
 
   if ((ptr = strchr (RaDatabase, '/')) != NULL) {
      *ptr++ = '\0';
      RaTable = ptr;

      if (ArgusParser->writeDbstr != NULL)
         snprintf (RaSQLSaveTable, MAXSTRLEN, "%s", RaTable);
   }

   if (!(ArgusParser->status & ARGUS_REAL_TIME_PROCESS))
      ArgusLastTime = ArgusParser->ArgusRealTime;

   MUTEX_INIT(&RaMySQLlock, NULL);
   if (MUTEX_LOCK(&RaMySQLlock) == 0) {

      if (RaMySQL == NULL)
         if ((RaMySQL = (void *) ArgusCalloc(1, sizeof(*RaMySQL))) == NULL)
            ArgusLog(LOG_ERR, "RaMySQLInit: ArgusCalloc error %s", strerror(errno));
    
      if ((mysql_init(RaMySQL)) == NULL)
         ArgusLog(LOG_ERR, "mysql_init error %s");

      if (!mysql_thread_safe())
         ArgusLog(LOG_INFO, "mysql not thread-safe");

      mysql_options(RaMySQL, MYSQL_READ_DEFAULT_GROUP, ArgusParser->ArgusProgramName);
      mysql_options(RaMySQL, MYSQL_OPT_RECONNECT, reconnect);

#ifdef ARGUSDEBUG
      ArgusDebug (2, "RaMySQLInit: connect %s %s %d\n", RaHost, RaUser, RaPort);
#endif

      if ((mysql_real_connect(RaMySQL, RaHost, RaUser, RaPass, NULL, RaPort, NULL, 0)) == NULL)
         ArgusLog(LOG_ERR, "mysql_connect error %s", mysql_error(RaMySQL));

      bzero(sbuf, sizeof(sbuf));
      sprintf (sbuf, "SHOW VARIABLES LIKE 'version'");

      if ((retn = mysql_real_query(RaMySQL, sbuf, strlen(sbuf))) != 0)
         ArgusLog(LOG_ERR, "MySQLInit: %s, mysql_real_query error %s", sbuf, mysql_error(RaMySQL));

      if ((mysqlRes = mysql_store_result(RaMySQL)) != NULL) {
         if ((retn = mysql_num_fields(mysqlRes)) > 0) {
            while ((row = mysql_fetch_row(mysqlRes))) {
               int matches = 0;
               unsigned long *lengths;
               lengths = mysql_fetch_lengths(mysqlRes);
               sprintf(sbuf, "%.*s", (int) lengths[1], row[1] ? row[1] : "NULL");

              ArgusSQLVersion = strdup(sbuf);
              if ((matches = sscanf(ArgusSQLVersion,"%d.%d.%d", &MySQLVersionMajor, &MySQLVersionMinor, &MySQLVersionSub)) > 0) {
               }
            }
         }
         mysql_free_result(mysqlRes);
      }

      bzero(sbuf, sizeof(sbuf));
      sprintf (sbuf, "SHOW VARIABLES LIKE 'bulk_insert_buffer_size'");

      if ((retn = mysql_real_query(RaMySQL, sbuf, strlen(sbuf))) != 0)
         ArgusLog(LOG_ERR, "MySQLInit: %s, mysql_real_query error %s", sbuf, mysql_error(RaMySQL));

      if ((mysqlRes = mysql_store_result(RaMySQL)) != NULL) {
         if ((retn = mysql_num_fields(mysqlRes)) > 0) {
            while ((row = mysql_fetch_row(mysqlRes))) {
               unsigned long *lengths;
               lengths = mysql_fetch_lengths(mysqlRes);
               sprintf(sbuf, "%.*s", (int) lengths[1], row[1] ? row[1] : "NULL");

              ArgusSQLBulkBufferSize = (int)strtol(sbuf, (char **)NULL, 10);
            }
         }
         mysql_free_result(mysqlRes);
      }

      bzero(sbuf, sizeof(sbuf));
      sprintf (sbuf, "SHOW VARIABLES LIKE 'max_allowed_packet'");

      if ((retn = mysql_real_query(RaMySQL, sbuf, strlen(sbuf))) != 0)
         ArgusLog(LOG_ERR, "MySQLInit: %s, mysql_real_query error %s", sbuf, mysql_error(RaMySQL));

      if ((mysqlRes = mysql_store_result(RaMySQL)) != NULL) {
         if ((retn = mysql_num_fields(mysqlRes)) > 0) {
            while ((row = mysql_fetch_row(mysqlRes))) {
               unsigned long *lengths;
               lengths = mysql_fetch_lengths(mysqlRes);
               sprintf(sbuf, "%.*s", (int) lengths[1], row[1] ? row[1] : "NULL");
               
              ArgusSQLMaxPacketSize = (int)strtol(sbuf, (char **)NULL, 10);
            }
         }
         mysql_free_result(mysqlRes);
      }

      ArgusSQLBulkInsertSize = (ArgusSQLMaxPacketSize < ArgusSQLBulkBufferSize) ? ArgusSQLMaxPacketSize : ArgusSQLBulkBufferSize;

      if ((ArgusSQLBulkBuffer = calloc(1, ArgusSQLBulkInsertSize)) == NULL)
         ArgusLog(LOG_WARNING, "ArgusMySQLInit: cannot alloc bulk buffer size %d\n", ArgusSQLBulkInsertSize);

      bzero(sbuf, sizeof(sbuf));
      sprintf (sbuf, "CREATE DATABASE IF NOT EXISTS %s", RaDatabase);

      if ((retn = mysql_real_query(RaMySQL, sbuf, strlen(sbuf))) != 0)  
         ArgusLog(LOG_ERR, "MySQLInit: %s, mysql_real_query error %s", sbuf, mysql_error(RaMySQL));

      sprintf (sbuf, "USE %s", RaDatabase);

      if ((retn = mysql_real_query(RaMySQL, sbuf, strlen(sbuf))) != 0)
         ArgusLog(LOG_ERR, "MySQLInit: %s, mysql_real_query error %s", sbuf, mysql_error(RaMySQL));

      if ((mysqlRes = mysql_list_tables(RaMySQL, NULL)) != NULL) {
         char sbuf[MAXSTRLEN];

         if ((retn = mysql_num_fields(mysqlRes)) > 0) {
            int thisIndex = 0;

            while ((row = mysql_fetch_row(mysqlRes))) {
               unsigned long *lengths;
               lengths = mysql_fetch_lengths(mysqlRes);
               bzero(sbuf, sizeof(sbuf));
                  for (x = 0; x < retn; x++)
                  sprintf(&sbuf[strlen(sbuf)], "%.*s", (int) lengths[x], row[x] ? row[x] : "NULL");

               RaTableExistsNames[thisIndex++] = strdup (sbuf);
            }

         } else {
#ifdef ARGUSDEBUG
            ArgusDebug (2, "mysql_num_fields() returned zero.\n");
#endif
         }
         mysql_free_result(mysqlRes);
      }

      if (ArgusParser->writeDbstr != NULL) {
         char *ptr;
         sprintf (ArgusParser->RaDBString, "-w %s", ArgusParser->writeDbstr);
         if ((ptr = strrchr(ArgusParser->writeDbstr, '/')) != NULL)
            *ptr = '\0';

      } else 
      if (ArgusParser->readDbstr != NULL) {
         char *ptr;
         sprintf (ArgusParser->RaDBString, "-r %s", ArgusParser->readDbstr);
         if ((ptr = strrchr(ArgusParser->readDbstr, '/')) != NULL)
            *ptr = '\0';
      } else  {
         sprintf (ArgusParser->RaDBString, "db %s", RaDatabase);

         if (RaHost)
            sprintf (&ArgusParser->RaDBString[strlen(ArgusParser->RaDBString)], "@%s", RaHost);

         sprintf (&ArgusParser->RaDBString[strlen(ArgusParser->RaDBString)], " user %s", RaUser);
      }
      MUTEX_UNLOCK(&RaMySQLlock);
   }

   if ((ArgusParser->ArgusInputFileList != NULL)  ||
        (ArgusParser->ArgusRemoteHosts && (ArgusParser->ArgusRemoteHosts->count > 0))) {

      if (strlen(RaSQLSaveTable) > 0) {
         if (!((strchr(RaSQLSaveTable, '%') || strchr(RaSQLSaveTable, '$'))))
            if (ArgusCreateSQLSaveTable(RaDatabase, RaSQLSaveTable))
               ArgusLog(LOG_ERR, "mysql create %s.%s returned error", RaDatabase, RaSQLSaveTable);
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (1, "RaMySQLInit () RaSource %s RaArchive %s RaFormat %s", RaSource, RaArchive, RaFormat);
#endif
}

/*
    So first look to see if the table already exists.
    If so and we're suppose to delete, then delete it.
    Then look to see if the name is in our list of default
    RaTableCreateNames[] to see if we need to remove it
    from that list, if we didn't catch the table in the
    other list.  At the end of this routine cindex is pointing 
    at the right place.
*/

extern int RaDaysInAMonth[12];

time_t ArgusTableStartSecs = 0;
time_t ArgusTableEndSecs = 0;



char *
ArgusCreateSQLSaveTableName (struct ArgusParserStruct *parser, struct ArgusRecordStruct *ns, char *table)
{
   struct ArgusAdjustStruct *nadp = &RaBinProcess->nadp;
   int timeLabel = 0, objectLabel = 0;
   char *retn = NULL;

   if (strchr(table, '%')) timeLabel = 1;
   if (strchr(table, '$')) objectLabel = 1;

   if (timeLabel || objectLabel) {
      int size = nadp->size / 1000000;
      long long start;
      time_t tableSecs;
      struct tm tmval;

      if (ns != NULL) 
         start = ArgusFetchStartuSecTime(ns);
      else 
         start = parser->ArgusRealTime.tv_sec * 1000000LL + parser->ArgusRealTime.tv_usec;
      
      if (timeLabel && (start == 0)) 
         return retn;

      tableSecs = start / 1000000;

      if (!(ArgusTableStartSecs) || !((tableSecs >= ArgusTableStartSecs) && (tableSecs < ArgusTableEndSecs))) {
         switch (nadp->qual) {
            case ARGUSSPLITYEAR:
            case ARGUSSPLITMONTH:
            case ARGUSSPLITWEEK: 
               gmtime_r(&tableSecs, &tmval);
               break;
         }

         switch (nadp->qual) {
            case ARGUSSPLITYEAR:
               tmval.tm_mon = 0;
            case ARGUSSPLITMONTH:
               tmval.tm_mday = 1;

            case ARGUSSPLITWEEK: 
               if (nadp->qual == ARGUSSPLITWEEK) {
                  if ((tmval.tm_mday - tmval.tm_wday) < 0) {
                     if (tmval.tm_mon == 0) {
                        if (tmval.tm_year != 0)
                           tmval.tm_year--;
                        tmval.tm_mon = 11;
                     } else {
                        tmval.tm_mon--;
                     }
                     tmval.tm_mday = RaDaysInAMonth[tmval.tm_mon];
                  }
                  tmval.tm_mday -= tmval.tm_wday;
               }

               tmval.tm_hour = 0;
               tmval.tm_min  = 0;
               tmval.tm_sec  = 0;
               tableSecs = timegm(&tmval);
               localtime_r(&tableSecs, &tmval);

#if defined(HAVE_TM_GMTOFF)
               tableSecs -= tmval.tm_gmtoff;
#endif
               break;

            case ARGUSSPLITDAY:
            case ARGUSSPLITHOUR:
            case ARGUSSPLITMINUTE:
            case ARGUSSPLITSECOND: {
               localtime_r(&tableSecs, &tmval);
#if defined(HAVE_TM_GMTOFF)
               tableSecs += tmval.tm_gmtoff;
#endif
               tableSecs = tableSecs / size;
               tableSecs = tableSecs * size;
#if defined(HAVE_TM_GMTOFF)
               tableSecs -= tmval.tm_gmtoff;
#endif
               break;
            }
         }

         localtime_r(&tableSecs, &tmval);

         if (strftime(ArgusSQLSaveTableNameBuf, MAXSTRLEN, table, &tmval) <= 0)
            ArgusLog (LOG_ERR, "ArgusCreateSQLSaveTableName () strftime %s\n", strerror(errno));

         RaProcessSplitOptions(ArgusParser, ArgusSQLSaveTableNameBuf, MAXSTRLEN, ns);

         ArgusTableStartSecs = tableSecs;

         switch (nadp->qual) {
            case ARGUSSPLITYEAR:  
               tmval.tm_year++;
               ArgusTableEndSecs = mktime(&tmval);
               break;
            case ARGUSSPLITMONTH:
               tmval.tm_mon++;
               ArgusTableEndSecs = mktime(&tmval);
               break;
            case ARGUSSPLITWEEK: 
            case ARGUSSPLITDAY: 
            case ARGUSSPLITHOUR: 
            case ARGUSSPLITMINUTE: 
            case ARGUSSPLITSECOND: 
               ArgusTableEndSecs = tableSecs + size;
               break;
         }
      }

      retn = ArgusSQLSaveTableNameBuf;

   } else {
      bcopy(ArgusSQLSaveTableNameBuf, table, strlen(table));
      retn = ArgusSQLSaveTableNameBuf;
   }

   return (retn);
}

char *ArgusGetSQLSaveTable(void);

char *
ArgusGetSQLSaveTable()
{
   char *retn = NULL;

   if (MUTEX_LOCK(&RaMySQLlock) == 0) {
      if (RaSQLCurrentTable && (strlen(RaSQLCurrentTable) > 0))
         retn = strdup(RaSQLCurrentTable);

      MUTEX_UNLOCK(&RaMySQLlock);
   }

   return retn;
}

int
ArgusCreateSQLSaveTable(char *db, char *table)
{
   int retn = 0, cindex = 0, ind = 0, i, x, exists = 0;
   struct ArgusMaskStruct *ArgusMaskDefs = ArgusIpV4MaskDefs; 
   char stable[1024], sbuf[MAXSTRLEN], kbuf[MAXSTRLEN];
   MYSQL_RES *mysqlRes;

   MUTEX_LOCK(&RaMySQLlock);

   if ((db != NULL) && (table != NULL)) {
      sprintf (stable, "%s.%s", db, table);
      bzero(sbuf, sizeof(sbuf));
      bzero(kbuf, sizeof(kbuf));

      sprintf (sbuf, "SHOW TABLES LIKE '%s'", table);
      if ((retn = mysql_real_query(RaMySQL, sbuf, strlen(sbuf))) != 0)
         ArgusLog(LOG_INFO, "ArgusCreateSQLSaveTable: mysql_real_query %s error %s", sbuf, mysql_error(RaMySQL));

      if ((mysqlRes = mysql_store_result(RaMySQL)) != NULL) {
         exists = mysql_num_rows(mysqlRes);
         mysql_free_result(mysqlRes);
      }

      if (ArgusDropTable) {
         if (exists) {
#ifdef ARGUSDEBUG
            ArgusDebug (2, "ArgusCreateSQLSaveTable: drop table %s\n", table);
#endif
            sprintf (sbuf, "DROP TABLE %s", table);
            if ((retn = mysql_real_query(RaMySQL, sbuf, strlen(sbuf))) != 0)
               ArgusLog(LOG_ERR, "MySQLInit: %s, mysql_real_query error %s", sbuf, mysql_error(RaMySQL));
            exists = 0;
         }
      }

      if (!exists) {
         RaTableCreateNames[cindex] = strdup(stable);

         sprintf (sbuf, "CREATE table %s (", RaTableCreateNames[cindex]);
         ind = 0;

         for (i = 0; i < MAX_PRINT_ALG_TYPES; i++) {
            if (ArgusParser->RaPrintAlgorithmList[i] != NULL) {
               ArgusParser->RaPrintAlgorithm = ArgusParser->RaPrintAlgorithmList[i];

               if ((ArgusAutoId == 0) && !strncmp(ArgusParser->RaPrintAlgorithm->field, "autoid", 6))
                  ArgusAutoId = 1;

               for (x = 0; x < ARGUS_MAX_PRINT_ALG; x++) {
                  if (!strcmp(ArgusParser->RaPrintAlgorithm->field, RaPrintAlgorithmTable[x].field)) {
                     if (ind++ > 0)
                        sprintf (&sbuf[strlen(sbuf)], ",");

                     sprintf (&sbuf[strlen(sbuf)], "%s %s", RaPrintAlgorithmTable[x].field, RaPrintAlgorithmTable[x].dbformat);
                     break;
                  }
               }
            }
         }

         if ((ArgusParser->ArgusAggregator != NULL) || ArgusAutoId) {
            struct ArgusAggregatorStruct *agg = ArgusParser->ArgusAggregator;

            long long mask = 0;
            int status = 0;

            while (agg != NULL) {
               mask |= agg->mask;
               status |= agg->status;
               agg = agg->nxt;
            }

            if (mask || ArgusAutoId) {
               ind = 0;
               sprintf (kbuf, "primary key (");

               if (ArgusAutoId) {
                  sprintf (&kbuf[strlen(kbuf)], "autoid");
                  ind++;
               }

               if (mask) {
                  for (i = 0; i < ARGUS_MAX_MASK_LIST; i++) {
                     int found; 
                     if (mask & (0x01LL << i)) {
                        for (found = 0, x = 0; x < MAX_PRINT_ALG_TYPES; x++) {
                           if (ArgusParser->RaPrintAlgorithmList[x] != NULL) {
                              ArgusParser->RaPrintAlgorithm = ArgusParser->RaPrintAlgorithmList[x];
                              if (!strcmp(ArgusParser->RaPrintAlgorithm->field, ArgusMaskDefs[i].name)) {
                                 found = 1;
                                 break;
                              }
                           }
                        }

                        if (!found)
                           ArgusLog(LOG_ERR, "key field '%s' not in schema (-s option)",  ArgusMaskDefs[i].name);

                        for (x = 0; x < MAX_PRINT_ALG_TYPES; x++) {
                           if (!(strcasecmp (ArgusMaskDefs[i].name, RaPrintAlgorithmTable[x].field))) {
                              if (ind++ > 0)
                                 sprintf (&kbuf[strlen(kbuf)], ",");

                              sprintf (&kbuf[strlen(kbuf)], "%s", RaPrintAlgorithmTable[x].field);
                              break;
                           }
                        }
                     }
                  }
               }
               sprintf (&kbuf[strlen(kbuf)], ")");
            }
         }

         if (strlen(kbuf))
            sprintf (&sbuf[strlen(sbuf)], ", %s", kbuf);

         if (ArgusSOptionRecord)
            sprintf (&sbuf[strlen(sbuf)], ", record blob");

         if ((MySQLVersionMajor > 4) || ((MySQLVersionMajor == 4) &&
                                         (MySQLVersionMinor >= 1)))
            sprintf (&sbuf[strlen(sbuf)], ") ENGINE=%s", ArgusParser->MySQLDBEngine);
         else
            sprintf (&sbuf[strlen(sbuf)], ") TYPE=%s", ArgusParser->MySQLDBEngine);
         RaTableCreateString[cindex] = strdup(sbuf);

         cindex++;

         for (i = 0; i < cindex; i++) {
            char *str = NULL;
            if (RaTableCreateNames[i] != NULL) {
               if ((str = RaTableCreateString[i]) != NULL) {
#ifdef ARGUSDEBUG
                  ArgusDebug (2, "ArgusCreateSQLSaveTable: %s\n", str);
#endif
                  if ((retn = mysql_real_query(RaMySQL, str, strlen(str))) != 0)
                     ArgusLog(LOG_INFO, "MySQLInit: %s, mysql_real_query error %s", sbuf, mysql_error(RaMySQL));

                  ArgusCreateTable = 1;
                  RaSQLCurrentTable = strdup(stable);
               }
            }
         }

      } else {
         if (RaSQLCurrentTable == NULL)
            RaSQLCurrentTable = strdup(stable);
         retn = 0;
      }
   } else {
      char *tbl = RaSQLCurrentTable;
      RaSQLCurrentTable = NULL;
      free(tbl);

      for (i = 0; i < RA_MAXTABLES; i++) {
         if (RaTableCreateNames[i] != NULL){free (RaTableCreateNames[i]); RaTableCreateNames[i] = NULL;}
         if (RaTableCreateString[i] != NULL){free (RaTableCreateString[i]); RaTableCreateString[i] = NULL;}
      }
   }

   MUTEX_UNLOCK(&RaMySQLlock);

#ifdef ARGUSDEBUG
   ArgusDebug (1, "ArgusCreateSQLSaveTable (%s, %s) returning", db, table, retn);
#endif
   return (retn);
}


void
RaMySQLDeleteRecords(struct ArgusParserStruct *parser, struct ArgusRecordStruct *ns)
{

#if defined(ARGUS_MYSQL)
   if (RaSQLUpdateDB && strlen(RaSQLSaveTable)) {
      if (ns->htblhdr != NULL) {
         ArgusRemoveHashEntry(&ns->htblhdr);
         ns->htblhdr = NULL;
      }

      if (ns->hinthdr != NULL) {
         ArgusRemoveHashEntry(&ns->hinthdr);
         ns->hinthdr = NULL;
      }

      if (RaSQLDBDeletes)
         if (ArgusScheduleSQLQuery (ArgusParser, ArgusParser->ArgusAggregator, ns, RaSQLSaveTable, ARGUS_STOP) != 0)
            ArgusLog(LOG_ERR, "RaMySQLDeleteRecords: ArgusScheduleSQLQuery error %s", strerror(errno));
   }
#endif

   ArgusDeleteRecordStruct (parser, ns);

#ifdef ARGUSDEBUG
      ArgusDebug (4, "RaMySQLDeleteRecords (0x%x, 0x%x) done", parser, ns);
#endif
}


// We construct the mysql query here.
// Query can get big, so we have a real query, and a debug string representing the query.
// The structure of the query is 

// If we are inserting the record, ArgusSOptionRecord == 1, we need to generate a mysql escaped record.


int
ArgusScheduleSQLQuery (struct ArgusParserStruct *parser, struct ArgusAggregatorStruct *agg, struct ArgusRecordStruct *ns, char *tbl, int state)
{
   int retn = 0;

   if ((agg == NULL) || (agg->mask == 0))
      if (!(ns->status & ARGUS_SQL_INSERT))
         return retn;

   if (tbl != NULL) {
      char *tmpbuf = ArgusMalloc(MAXBUFFERLEN);
      char   *sbuf = ArgusMalloc(MAXBUFFERLEN);
      char   *mbuf = ArgusMalloc((ARGUS_MAXRECORDSIZE * 2) + 1);

      char tbuf[1024], fbuf[1024], ubuf[1024], *ptr, *tptr;
      char vbuf[1024], ibuf[1024];
      char *rbuf = NULL;

#ifdef ARGUSDEBUG
      char dbuf[MAXSTRLEN];
#endif
      struct ArgusMaskStruct *ArgusMaskDefs = ArgusIpV4MaskDefs;
      struct ArgusSQLQueryStruct *sqry = NULL;
      struct ArgusRecord *argus = NULL;

      int y, len, ind = 0, mind = 0, iind = 0;
      int  nflag, found, uflag;

      nflag = parser->nflag;
      parser->nflag = 2;

      bzero(sbuf, 8);
      tbuf[0] = '\0';
      fbuf[0] = '\0';
      ubuf[0] = '\0';
      vbuf[0] = '\0';
      ibuf[0] = '\0';

      if (ArgusSOptionRecord)
        rbuf = ArgusCalloc(1, ARGUS_MAXRECORDSIZE);

      MUTEX_LOCK(&parser->lock);

      for (parser->RaPrintIndex = 0; parser->RaPrintIndex < MAX_PRINT_ALG_TYPES; parser->RaPrintIndex++) {
         if (parser->RaPrintAlgorithmList[parser->RaPrintIndex] != NULL) {
            parser->RaPrintAlgorithm = parser->RaPrintAlgorithmList[parser->RaPrintIndex];

            if (strncmp(parser->RaPrintAlgorithm->field, "autoid", 6)) {
               int len = parser->RaPrintAlgorithm->length;
               len = (len > 256) ? len : 256;

               found = 0;
               *tmpbuf = '\0';

               if (agg && agg->mask) {
                  for (y = 0; y < ARGUS_MAX_MASK_LIST; y++) {
                     if (agg->mask & (0x01LL << y)) {
                        if (!strcmp(parser->RaPrintAlgorithm->field, ArgusMaskDefs[y].name)) {
                           found++;
                        }
                     }
                  }
               }

               if (ind++ > 0) {
                  sprintf (&fbuf[strlen(fbuf)], ",");
                  sprintf (&vbuf[strlen(vbuf)], ",");
               }

               if (found) {
                  if (mind++ > 0)
                     sprintf (&ubuf[strlen(ubuf)], " and ");
               } else {
                  if (iind++ > 0)
                     sprintf (&ibuf[strlen(ibuf)], ",");
               }

               uflag = ArgusParser->uflag;
               ArgusParser->uflag++;

               parser->RaPrintAlgorithm->print(parser, tmpbuf, ns, len);

               ArgusParser->uflag = uflag;

               if ((ptr = ArgusTrimString(tmpbuf)) != NULL) {
                  snprintf (tbuf, 1024, "\"%s\"", ptr);
                  tptr = &fbuf[strlen(fbuf)];
                  sprintf (tptr, "%s", tbuf);

                  snprintf (&vbuf[strlen(vbuf)], 1024, "%s", parser->RaPrintAlgorithm->field);
                  snprintf (tbuf, 1024, "%s=\"%s\"", parser->RaPrintAlgorithm->field, ptr);

                  if (found) {
                     tptr = &ubuf[strlen(ubuf)];
                     sprintf (tptr, "%s", tbuf);
                  } else {
                     tptr = &ibuf[strlen(ibuf)];
                     sprintf (tptr, "%s", tbuf);
                  }
               }
            }
         }
      }

      MUTEX_UNLOCK(&parser->lock);

      parser->nflag   = nflag;

      if (state != ARGUS_STOP) {
         len = 0;
         if (ArgusSOptionRecord) {
            int tlen;

            if ((argus = ArgusGenerateRecord (ns, 0L, rbuf)) == NULL)
               ArgusLog(LOG_ERR, "ArgusScheduleSQLQuery: ArgusGenerateRecord error %s", strerror(errno));
#ifdef _LITTLE_ENDIAN
            ArgusHtoN(argus);
#endif

            if ((tlen = ntohs(argus->hdr.len) * 4) < ARGUS_MAXRECORDSIZE) {
               if (MUTEX_LOCK(&RaMySQLlock) == 0) {
                  if ((len = mysql_real_escape_string(RaMySQL, mbuf, (char *)argus, tlen)) <= 0)
                     ArgusLog(LOG_ERR, "mysql_real_escape_string error %s", mysql_error(RaMySQL));
                  MUTEX_UNLOCK(&RaMySQLlock);
               }
            }
         }

         if (len < (MAXBUFFERLEN - (strlen(ibuf) + strlen(ubuf)))) {
            if (!(ns->status & ARGUS_SQL_INSERT)) {
               if (ArgusSOptionRecord) {
                  if (strlen(ibuf)) {
                     snprintf (sbuf, MAXBUFFERLEN, "UPDATE %s SET %s,record=\"%s\" WHERE %s", tbl, ibuf, mbuf, ubuf);
#ifdef ARGUSDEBUG
                     snprintf (dbuf, MAXSTRLEN, "UPDATE %s SET %s,record=\"...\" WHERE %s", tbl, ibuf, ubuf);
#endif
                  } else {
                     snprintf (sbuf, MAXBUFFERLEN, "UPDATE %s SET record=\"%s\" WHERE %s", tbl, mbuf, ubuf);
#ifdef ARGUSDEBUG
                     snprintf (dbuf, MAXSTRLEN, "UPDATE %s SET record=\"...\" WHERE %s", tbl, ubuf);
#endif
                  }
               } else {
                  snprintf (sbuf, MAXBUFFERLEN, "UPDATE %s SET %s WHERE %s", tbl, ibuf, ubuf);
#ifdef ARGUSDEBUG
                  snprintf (dbuf, MAXSTRLEN, "%s", sbuf);
#endif
               }
               ns->status |= ARGUS_SQL_UPDATE;

            } else {
               if (ArgusSOptionRecord) {
                  int slen, tlen;

                  snprintf (sbuf, MAXBUFFERLEN, "INSERT INTO %s (%s,record) VALUES (%s,\"", tbl, vbuf, fbuf);
#ifdef ARGUSDEBUG
                  snprintf (dbuf, MAXSTRLEN, "INSERT INTO %s (%s,record) VALUES (%s,...)", tbl, vbuf, fbuf);
#endif
                  slen = strlen(sbuf);

                  if ((tlen = (slen + len)) < (MAXBUFFERLEN - 3))  {
                     bcopy(mbuf, &sbuf[slen], len + 1);
                     snprintf (&sbuf[tlen], MAXBUFFERLEN - tlen, "\")");
                  } else {
                     snprintf (&sbuf[slen], MAXBUFFERLEN - slen, "\")");
                  }

               } else {
                  snprintf (sbuf, MAXBUFFERLEN, "INSERT INTO %s (%s) VALUES (%s)", tbl, vbuf, fbuf);
#ifdef ARGUSDEBUG
                  snprintf (dbuf, MAXSTRLEN, "%s", sbuf);
#endif
               }

#ifdef ARGUSDEBUG
               ArgusDebug (3, "ArgusScheduleSQLQuery (0x%x, 0x%x, 0x%x, %s, %s, %d) done\n", parser, agg, ns, tbl, dbuf, state);
#endif
            }

         } else {
#ifdef ARGUSDEBUG
            ArgusDebug (3, "ArgusScheduleSQLQuery: query too large for allocated buffer\n", len);
#endif
         }

      } else {
         ns->status &= ~(ARGUS_SQL_STATUS);
         ns->status |= ARGUS_SQL_DELETE;

         snprintf (sbuf, MAXBUFFERLEN, "DELETE FROM %s WHERE %s", tbl, ubuf);
#ifdef ARGUSDEBUG
         snprintf (dbuf, MAXSTRLEN, "%s", sbuf);
         ArgusDebug (3, "ArgusScheduleSQLQuery (0x%x, 0x%x, 0x%x, %s, %s, %d) done\n", parser, agg, ns, tbl, dbuf, state);
#endif
      }

      ns->qhdr.logtime = ArgusParser->ArgusRealTime;

      if ((sqry = (void *) ArgusCalloc(1, sizeof(*sqry))) == NULL)
         ArgusLog(LOG_ERR, "ArgusScheduleSQLQuery: ArgusCalloc error %s", strerror(errno));

      sqry->tbl  = strdup(tbl);
      sqry->sptr = strdup(sbuf);
#ifdef ARGUSDEBUG
      sqry->dptr = strdup(dbuf);
#endif
      switch (ns->status & ARGUS_SQL_STATUS) {
         case ARGUS_SQL_INSERT:  
            ArgusPushBackList (ArgusSQLInsertQueryList, (struct ArgusListRecord *)&sqry->nxt, ARGUS_LOCK);
            COND_SIGNAL(&ArgusSQLInsertQueryList->cond);
            break;
         case ARGUS_SQL_UPDATE:  
            ArgusPushBackList (ArgusSQLUpdateQueryList, (struct ArgusListRecord *)&sqry->nxt, ARGUS_LOCK);
            COND_SIGNAL(&ArgusSQLUpdateQueryList->cond);
            break;
         case ARGUS_SQL_DELETE:  
            ArgusPushBackList (ArgusSQLSelectQueryList, (struct ArgusListRecord *)&sqry->nxt, ARGUS_LOCK);
            COND_SIGNAL(&ArgusSQLSelectQueryList->cond);
            break;
      }

      ns->status &= ~(ARGUS_SQL_STATUS);

      if (tmpbuf) ArgusFree(tmpbuf);
      if (  mbuf) ArgusFree(mbuf);
      if (  sbuf) ArgusFree(sbuf);
      if (  rbuf) ArgusFree(rbuf);
   }

   return (retn);
}


#endif
