/*
 * Gargoyle Client Software. Tools to read, analyze and manage Argus data.
 * Copyright (c) 2000-2017 QoSient, LLC
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
 */

/* 
 * $Id: //depot/gargoyle/clients/include/argus_label.h#32 $
 * $DateTime: 2016/06/01 10:28:03 $
 * $Change: 3143 $
 */

#ifndef ArgusLabeler_h
#define ArgusLabeler_h

#ifdef __cplusplus
extern "C" {
#endif

#if defined(ARGUS_GEOIP)
#include <GeoIP.h>
#endif

#if defined(ARGUS_GEOIP2)
#include <maxminddb.h>
#endif

#define ARGUS_LABELER_DEBUG	    0x0100
#define ARGUS_LABELER_DEBUG_LOCAL   0x0200
#define ARGUS_LABELER_DEBUG_NODE    0x0400

#define ARGUS_TREE_DEBUG	    0x0100
#define ARGUS_TREE_DEBUG_LOCAL      0x0200
#define ARGUS_TREE_DEBUG_NODE       0x0400

#define ARGUS_LABELER_COCODE	    0x01
#define ARGUS_LABELER_ADDRESS	    0x02

#define ARGUS_TREE                  0x01
#define ARGUS_TREE_VISITED          0x02
#define ARGUS_TREE_POPULATED        0x04
#define ARGUS_NODE                  0x08
#define ARGUS_VISITED               0x10

#define ARGUS_NEWICK                0x20
#define ARGUS_GRAPH                 0x40
#define ARGUS_JSON                  0x80

#define ARGUS_UNION		    0x01
#define ARGUS_INTERSECT		    0x02
#define ARGUS_REPLACE		    0x03


#define ARGUS_TREE_PRUNE_LABEL      0x00
#define ARGUS_TREE_PRUNE_CCO        0x01
#define ARGUS_TREE_PRUNE_LOCALITY   0x02
#define ARGUS_TREE_PRUNE_RECORD     0x03

#define ARGUS_TREE_PRUNE_ADJ        0x10
#define ARGUS_TREE_PRUNE_ANY        0x20

#define ARGUS_TREE_DNS_TLD          0x40
#define ARGUS_TREE_DNS_SLD          0x80

struct ArgusGeoIPCityObject {
   char *field, *format;
   int length, index, offset, value;
};
 
struct ArgusLabelerStruct {
   int status, mask, inserts, prune, count;
   int RaPrintLabelTreeMode;
   int RaLabelIanaAddress;
   int RaLabelIeeeAddress;
   int RaLabelCountryCode;
   int RaLabelBindName;
   int RaLabelIanaPort;
   int RaLabelArgusFlow;
   int RaLabelLocality;
   int RaLabelLocalityOverwrite;
   int RaLabelLocalityInterfaceIsMe;

#if defined(ARGUS_GEOIP) && !defined(ARGUS_GEOIP2)
   int RaLabelGeoIPAsn;
   GeoIP *RaGeoIPv4AsnObject;
   GeoIP *RaGeoIPv6AsnObject;

   int RaLabelGeoIPCity;
   GeoIP *RaGeoIPv4CityObject;
   GeoIP *RaGeoIPv6CityObject;
   int RaLabelGeoIPCityLabels[16];
#endif

#if defined(ARGUS_GEOIP2) && !defined(ARGUS_GEOIP)
   int RaLabelGeoIPAsn;
   MMDB_s RaGeoIPAsnObject;

   int RaLabelGeoIPCity;
   MMDB_s RaGeoIPCityObject;
   int RaLabelGeoIPCityLabels[16];
#endif

   struct RaPolicyStruct *drap, *rap;
   struct RaFlowModelStruct *fmodel;
   struct ArgusQueueStruct *queue;
   struct ArgusHashTable htable;
   struct ArgusHashStruct hstruct;

   struct RaAddressStruct **ArgusAddrTree;
   struct RaAddressStruct **ArgusRIRTree;

   struct RaPortStruct **ArgusTCPPortLabels;
   struct RaPortStruct **ArgusUDPPortLabels;
   struct ArgusQueueStruct *ArgusFlowQueue;
};

#define ARGUS_EXACT_MATCH       0x00
#define ARGUS_LONGEST_MATCH     0x01
#define ARGUS_ANY_MATCH         0x02
#define ARGUS_NODE_MATCH        0x04
#define ARGUS_MASK_MATCH        0x05
#define ARGUS_SUPER_MATCH       0x06

struct RaAddressStruct {
   struct ArgusQueueHeader qhdr;
   struct RaAddressStruct *l, *r, *p;
   struct ArgusRecordStruct *ns;

   struct ArgusCIDRAddr addr;

   int type, status, offset, count, ttl;
   struct timeval atime, rtime;
   char *str, *label, *asnlabel;

   struct ArgusListStruct *dns;
   void *obj;

   float lat, lon, x, y, z;
   int locality;
   uint32_t asn;
   char cco[4];
};


struct RaPortStruct {
   struct ArgusQueueHeader qhdr;
   unsigned short proto, start, end;
   int offset, count, status;
   char *label, *desc;
};


struct RaFlowLabelStruct {
   struct ArgusQueueHeader qhdr;
   int status, cont;
   char *filterstr, *labelstr, *grepstr, *colorstr;
   struct nff_program filter;
};


#if defined(ArgusLabel)

/*
struct ArgusGeoIPCityObject {
   char *field, *format;
   int length, index, offset, value;
}
*/

#define ARGUS_GEOIP_TOTAL_OBJECTS       14

struct ArgusGeoIPCityObject ArgusGeoIPCityObjects[ARGUS_GEOIP_TOTAL_OBJECTS] = {
   { "", "%s", 0, 0, 0, 0},
#define ARGUS_GEOIP_COUNTRY_CODE        1
   { "cco", "%s", 3, 2, 0, ARGUS_GEOIP_COUNTRY_CODE},
#define ARGUS_GEOIP_COUNTRY_CODE_3      2
   { "cco3", "%s", 4, 3, 0, ARGUS_GEOIP_COUNTRY_CODE_3},
#define ARGUS_GEOIP_COUNTRY_NAME        3
   { "cname", "%s", 5, 128, 0, ARGUS_GEOIP_COUNTRY_NAME},
#define ARGUS_GEOIP_REGION              4
   { "region", "%s", 6, 128, 0, ARGUS_GEOIP_REGION},
#define ARGUS_GEOIP_CITY_NAME           5
   { "city", "%s", 4, 128, 0, ARGUS_GEOIP_CITY_NAME},
#define ARGUS_GEOIP_POSTAL_CODE         6
   { "pcode", "%s", 5, 16, 0, ARGUS_GEOIP_POSTAL_CODE},
#define ARGUS_GEOIP_LATITUDE            7
   { "lat", "%f", 3, 16, 0, ARGUS_GEOIP_LATITUDE},
#define ARGUS_GEOIP_LONGITUDE           8
   { "lon", "%f", 3, 16, 0, ARGUS_GEOIP_LONGITUDE},
#define ARGUS_GEOIP_METRO_CODE          9
   { "metro", "%d", 5, 16, 0, ARGUS_GEOIP_METRO_CODE},
#define ARGUS_GEOIP_AREA_CODE           10
   { "area", "%d", 4, 16, 0, ARGUS_GEOIP_AREA_CODE},
#define ARGUS_GEOIP_CHARACTER_SET       11
   { "charset", "%d", 7, 16, 0, ARGUS_GEOIP_CHARACTER_SET},
#define ARGUS_GEOIP_CONTINENT_CODE      12
   { "cont", "%s", 4, 16, 0, ARGUS_GEOIP_CONTINENT_CODE},
#define ARGUS_GEOIP_NETMASK             13
   { "netmask", "%d", 7, 4, 0, ARGUS_GEOIP_NETMASK},
};

int RaLabelParseResourceFile (struct ArgusParserStruct *, struct ArgusLabelerStruct *, char *);
int RaLabelParseResourceBuffer (struct ArgusParserStruct *, struct ArgusLabelerStruct *, char **);
int RaLabelParseResourceStr (struct ArgusParserStruct *, struct ArgusLabelerStruct *, char *);

struct ArgusLabelerStruct *ArgusNewLabeler (struct ArgusParserStruct *, int);
void ArgusDeleteLabeler (struct ArgusParserStruct *, struct ArgusLabelerStruct *);

struct ArgusLabelerStruct *ArgusLabeler = NULL;
int ArgusAddToRecordLabel (struct ArgusParserStruct *, struct ArgusRecordStruct *, char *);

struct ArgusRecordStruct *ArgusLabelRecord (struct ArgusParserStruct *, struct ArgusRecordStruct *);

void ArgusGetInterfaceAddresses(struct ArgusParserStruct *);
void RaPrintLabelTree (struct ArgusLabelerStruct *, struct RaAddressStruct *, int, int);

struct RaAddressStruct *RaFindAddress (struct ArgusParserStruct *, struct RaAddressStruct *, struct RaAddressStruct *, int);
struct RaAddressStruct *RaInsertAddress (struct ArgusParserStruct *, struct ArgusLabelerStruct *, struct RaAddressStruct *, struct RaAddressStruct *, int);

int RaInsertAddressTree (struct ArgusParserStruct *, struct ArgusLabelerStruct *labeler, char *);
int RaInsertLocalityTree (struct ArgusParserStruct *, struct ArgusLabelerStruct *labeler, char *);

char *RaPruneAddressTree (struct ArgusLabelerStruct *, struct RaAddressStruct *, int, int);

void RaLabelMaskAddressStatus(struct RaAddressStruct *, unsigned int);

int RaReadAddressConfig (struct ArgusParserStruct *, struct ArgusLabelerStruct *, char *);
int RaReadLocalityConfig (struct ArgusParserStruct *, struct ArgusLabelerStruct *, char *);
int RaReadPortConfig (struct ArgusParserStruct *, struct ArgusLabelerStruct *, char *);
int RaReadFlowLabels (struct ArgusParserStruct *, struct ArgusLabelerStruct *, char *);

void RaMapLabelMol (struct ArgusLabelerStruct *, struct RaAddressStruct *, int, int, int, int);
void RaPrintLabelMol (struct ArgusLabelerStruct *, struct RaAddressStruct *, int, int, int, int);
void RaPrintLabelTree (struct ArgusLabelerStruct *, struct RaAddressStruct *, int, int);

int RaCountryCodeLabel (struct ArgusParserStruct *, struct ArgusRecordStruct *);
char *RaAddressLabel (struct ArgusParserStruct *, struct ArgusRecordStruct *);
char *RaLocalityLabel (struct ArgusParserStruct *, struct ArgusRecordStruct *);
char *RaLabelIANAAddressType (struct ArgusParserStruct *, struct ArgusRecordStruct *);
char *RaFetchIPv4AddressLabel(struct ArgusParserStruct *, unsigned int *);
char *RaPortLabel (struct ArgusParserStruct *, struct ArgusRecordStruct *, char *, int);
char *RaFlowLabel (struct ArgusParserStruct *, struct ArgusRecordStruct *, char *, int);
char *RaFlowColor (struct ArgusParserStruct *, struct ArgusRecordStruct *);
char *RaFetchIPPortLabel(struct ArgusParserStruct *, unsigned short, unsigned short);

#else

#define ARGUS_GEOIP_COUNTRY_CODE        1
#define ARGUS_GEOIP_COUNTRY_CODE_3      2
#define ARGUS_GEOIP_COUNTRY_NAME        3
#define ARGUS_GEOIP_REGION              4
#define ARGUS_GEOIP_CITY_NAME           5
#define ARGUS_GEOIP_POSTAL_CODE         6
#define ARGUS_GEOIP_LATITUDE            7
#define ARGUS_GEOIP_LONGITUDE           8
#define ARGUS_GEOIP_METRO_CODE          9
#define ARGUS_GEOIP_AREA_CODE           10
#define ARGUS_GEOIP_CHARACTER_SET       11
#define ARGUS_GEOIP_CONTINENT_CODE      12
#define ARGUS_GEOIP_NETMASK             13

extern int RaLabelParseResourceFile (struct ArgusParserStruct *, struct ArgusLabelerStruct *, char *);
extern int RaLabelParseResourceBuffer (struct ArgusParserStruct *, struct ArgusLabelerStruct *, char **);
extern int RaLabelParseResourceStr (struct ArgusParserStruct *, struct ArgusLabelerStruct *, char *);

extern struct ArgusLabelerStruct *ArgusNewLabeler (struct ArgusParserStruct *, int);
extern void ArgusDeleteLabeler (struct ArgusParserStruct *, struct ArgusLabelerStruct *);
extern struct ArgusLabelerStruct *ArgusLabeler;
extern void RaPrintLabelTree (struct ArgusLabelerStruct *, struct RaAddressStruct *, int, int);

extern void ArgusGetInterfaceAddresses(struct ArgusParserStruct *);

extern struct ArgusRecordStruct *ArgusLabelRecord (struct ArgusParserStruct *, struct ArgusRecordStruct *);
extern int ArgusAddToRecordLabel (struct ArgusParserStruct *, struct ArgusRecordStruct *, char *);

extern struct RaAddressStruct *RaFindAddress (struct ArgusParserStruct *, struct RaAddressStruct *, struct RaAddressStruct *, int);
extern struct RaAddressStruct *RaInsertAddress (struct ArgusParserStruct *, struct ArgusLabelerStruct *, struct RaAddressStruct *, struct RaAddressStruct *, int);

extern int RaInsertAddressTree (struct ArgusParserStruct *, struct ArgusLabelerStruct *labeler, char *);
extern int RaInsertLocalityTree (struct ArgusParserStruct *, struct ArgusLabelerStruct *labeler, char *);

extern char *RaPruneAddressTree (struct ArgusLabelerStruct *, struct RaAddressStruct *, int, int);

extern void RaLabelMaskAddressStatus(struct RaAddressStruct *, unsigned int);

extern int RaReadAddressConfig (struct ArgusParserStruct *, struct ArgusLabelerStruct *, char *);
extern int RaReadLocalityConfig (struct ArgusParserStruct *, struct ArgusLabelerStruct *, char *);
extern int RaReadPortConfig (struct ArgusParserStruct *, struct ArgusLabelerStruct *, char *);
extern int RaReadFlowLabels (struct ArgusParserStruct *, struct ArgusLabelerStruct *, char *);

extern void RaMapLabelMol (struct ArgusLabelerStruct *, struct RaAddressStruct *, int, int, int, int);
extern void RaPrintLabelMol (struct ArgusLabelerStruct *, struct RaAddressStruct *, int, int, int, int);
extern void RaPrintLabelTree (struct ArgusLabelerStruct *, struct RaAddressStruct *, int, int);

extern int RaCountryCodeLabel (struct ArgusParserStruct *, struct ArgusRecordStruct *);
extern char *RaAddressLabel (struct ArgusParserStruct *, struct ArgusRecordStruct *);
extern char *RaLocalityLabel (struct ArgusParserStruct *, struct ArgusRecordStruct *);
extern char *RaLabelIANAAddressType (struct ArgusParserStruct *, struct ArgusRecordStruct *);
extern char *RaFetchIPv4AddressLabel(struct ArgusParserStruct *, unsigned int *);
extern char *RaPortLabel (struct ArgusParserStruct *, struct ArgusRecordStruct *, char *, int);
extern char *RaFlowLabel (struct ArgusParserStruct *, struct ArgusRecordStruct *, char *, int);
extern char *RaFlowColor (struct ArgusParserStruct *, struct ArgusRecordStruct *);
extern char *RaFetchIPPortLabel(struct ArgusParserStruct *, unsigned short, unsigned short);

#endif
#ifdef __cplusplus
}
#endif
#endif

