/*
 * Gargoyle Client Software. Tools to read, analyze and manage Argus data.
 * Copyright (c) 2000-2018 QoSient, LLC
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


#ifdef HAVE_CONFIG_H
#include "argus_config.h"
#endif

#if defined(ARGUS_GEOIP)

#ifndef ArgusLabel
#define ArgusLabel
#endif

#ifndef _REENTRANT
#define _REENTRANT
#endif

#include <stdlib.h>
#include <syslog.h>
#include <errno.h>
#include <ctype.h>
#include <sys/types.h>

#include <argus_compat.h>
#include <argus_def.h>
#include <argus_out.h>
#include <argus_util.h>
#include <argus_client.h>
#include <argus_sort.h>
#include <argus_metric.h>
#include <argus_label.h>

#if defined(__OpenBSD__)
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#endif

#include <netinet/ip_icmp.h>
#include <netinet/igmp.h>
#include <netinet/tcp.h>

#include <GeoIPCity.h>
#include "argus_label_geoip.h"

struct ArgusGeoIPCityObject ArgusGeoIPCityObjects[] = {
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

static int
ArgusPrintGeoIPRecord(struct ArgusParserStruct *parser, GeoIPRecord *gir,
                      char *label, int len, int found, char *prefix)
{
   int slen = strlen(label), x, tf = 0;

   if (found) {
      snprintf (&label[slen], len - slen, ":");
      slen++;
   }

   snprintf (&label[slen], len - slen, "%s", prefix);
   slen = strlen(label);

   for (x = 0; x < ARGUS_GEOIP_TOTAL_OBJECTS; x++) {
      struct ArgusGeoIPCityObject *obj;
      int ind;
      if ((ind = parser->ArgusLabeler->RaLabelGeoIPCityLabels[x]) > 0) {
         if (tf) {
            snprintf (&label[slen], len - slen, "%c", ',');
            slen++;
         }
         obj = &ArgusGeoIPCityObjects[ind];
         switch (obj->value) {
            case ARGUS_GEOIP_COUNTRY_CODE:
               snprintf (&label[slen], len - slen, obj->format, gir->country_code);
               break;
            case ARGUS_GEOIP_COUNTRY_CODE_3:
               snprintf (&label[slen], len - slen, obj->format, gir->country_code3);
               break;
            case ARGUS_GEOIP_COUNTRY_NAME:
               snprintf (&label[slen], len - slen, obj->format, gir->country_name);
               break;
            case ARGUS_GEOIP_REGION:
               snprintf (&label[slen], len - slen, obj->format, gir->region);
               break;
            case ARGUS_GEOIP_CITY_NAME:
               snprintf (&label[slen], len - slen, obj->format, gir->city);
               break;
            case ARGUS_GEOIP_POSTAL_CODE:
               snprintf (&label[slen], len - slen, obj->format, gir->postal_code);
               break;
            case ARGUS_GEOIP_LATITUDE:
               snprintf (&label[slen], len - slen, obj->format, gir->latitude);
               break;
            case ARGUS_GEOIP_LONGITUDE:
               snprintf (&label[slen], len - slen, obj->format, gir->longitude);
               break;
            case ARGUS_GEOIP_METRO_CODE:
               snprintf (&label[slen], len - slen, obj->format, gir->metro_code);
               break;
            case ARGUS_GEOIP_AREA_CODE:
               snprintf (&label[slen], len - slen, obj->format, gir->area_code);
               break;
            case ARGUS_GEOIP_CHARACTER_SET:
               snprintf (&label[slen], len - slen, obj->format, gir->charset);
               break;
            case ARGUS_GEOIP_CONTINENT_CODE:
               snprintf (&label[slen], len - slen, obj->format, gir->continent_code);
               break;
//          case ARGUS_GEOIP_NETMASK:
//             snprintf (&label[slen], len - slen, obj->format, gir->netmask);
//             break;
         }
         slen = strlen(label);
         tf++;

      } else
         break;
   }

   return found;
}

int
ArgusLabelRecordGeoIP(struct ArgusParserStruct *parser,
                      struct ArgusRecordStruct *argus,
                      char *label, size_t len,
                      int *found)
{
   int _found = *found;
   struct ArgusLabelerStruct *labeler = parser->ArgusLabeler;

   if (labeler->RaLabelGeoIPAsn) {
      if (labeler->RaGeoIPv4AsnObject != NULL) {
         struct ArgusAsnStruct *asn = (struct ArgusAsnStruct *) argus->dsrs[ARGUS_ASN_INDEX];
         struct ArgusFlow *flow = (struct ArgusFlow *) argus->dsrs[ARGUS_FLOW_INDEX];
         struct ArgusIcmpStruct *icmp = (void *)argus->dsrs[ARGUS_ICMP_INDEX];
         char *rstr;

         if (flow != NULL) {
            if (asn == NULL) {
               if ((asn = ArgusCalloc(1, sizeof(*asn))) == NULL)
                  ArgusLog (LOG_ERR, "RaProcessRecord: ArgusCalloc error %s", strerror(errno));

               asn->hdr.type              = ARGUS_ASN_DSR;
               asn->hdr.subtype           = ARGUS_ASN_ORIGIN;
               asn->hdr.argus_dsrvl8.qual = 0;
               asn->hdr.argus_dsrvl8.len  = 3;

               argus->dsrs[ARGUS_ASN_INDEX] = (struct ArgusDSRHeader *) asn;
               argus->dsrindex |= (0x01 << ARGUS_ASN_INDEX);
            }

            switch (flow->hdr.subtype & 0x3F) {
               case ARGUS_FLOW_CLASSIC5TUPLE:
               case ARGUS_FLOW_LAYER_3_MATRIX: {
                  switch (flow->hdr.argus_dsrvl8.qual & 0x1F) {
                     case ARGUS_TYPE_IPV4: {
                        if (asn->src_as == 0) {
                           if ((rstr = GeoIP_org_by_ipnum (labeler->RaGeoIPv4AsnObject, flow->ip_flow.ip_src)) != NULL) {
                              if (strlen(rstr)) {
                                 int result = 0;
                                 if (sscanf(rstr, "AS%d", &result) == 1)
                                    asn->src_as = result;
                              }
                              free(rstr);
                           }
                        }

                        if (asn->dst_as == 0) {
                           if ((rstr = GeoIP_org_by_ipnum (labeler->RaGeoIPv4AsnObject, flow->ip_flow.ip_dst)) != NULL) {
                              if (strlen(rstr)) {
                                 int result = 0;
                                 if (sscanf(rstr, "AS%d", &result) == 1)
                                    asn->dst_as = result;
                              }
                              free(rstr);
                           }
                        }

                        if (asn->inode_as == 0) {
                           if (icmp != NULL) {
                              if (icmp->hdr.argus_dsrvl8.qual & ARGUS_ICMP_MAPPED) {
                                 if ((rstr = GeoIP_org_by_ipnum (labeler->RaGeoIPv4AsnObject, icmp->osrcaddr)) != NULL) {
                                    if (strlen(rstr)) {
                                       int result = 0;
                                       if (sscanf(rstr, "AS%d", &result) == 1)
                                          asn->inode_as = result;

                                       asn->hdr.argus_dsrvl8.len  = 4;
                                    }
                                    free(rstr);
                                 }
                              }
                           }
                        }
                        break;
                     }

                     case ARGUS_TYPE_IPV6: {
                        if (labeler->RaGeoIPv6AsnObject) {
                           if (asn->src_as == 0) {
                              struct in6_addr saddr;

                              bcopy(flow->ipv6_flow.ip_src, saddr.s6_addr, sizeof(saddr));

                              if ((rstr = GeoIP_org_by_ipnum_v6 (labeler->RaGeoIPv6AsnObject, saddr)) != NULL) {
                                 if (strlen(rstr)) {
                                    int result = 0;
                                    if (sscanf(rstr, "AS%d", &result) == 1)
                                       asn->src_as = result;
                                 }
                                 free(rstr);
                              }
                           }

                           if (asn->dst_as == 0) {
                              struct in6_addr daddr;

                              bcopy(flow->ipv6_flow.ip_dst, daddr.s6_addr, sizeof(daddr));

                              if ((rstr = GeoIP_org_by_ipnum_v6 (labeler->RaGeoIPv6AsnObject, daddr)) != NULL) {
                                 if (strlen(rstr)) {
                                    int result = 0;
                                    if (sscanf(rstr, "AS%d", &result) == 1)
                                       asn->dst_as = result;
                                 }
                                 free(rstr);
                              }
                           }
                        }
                        break;
                     }
                  }
                  break;
               }
            }
         }
      }
   }

   if (labeler->RaLabelGeoIPCity) {
      if (labeler->RaGeoIPv4CityObject != NULL) {
         struct ArgusFlow *flow = (struct ArgusFlow *) argus->dsrs[ARGUS_FLOW_INDEX];
         GeoIPRecord *gir;

         if (flow != NULL) {
            switch (flow->hdr.subtype & 0x3F) {
               case ARGUS_FLOW_CLASSIC5TUPLE:
               case ARGUS_FLOW_LAYER_3_MATRIX: {
                  switch (flow->hdr.argus_dsrvl8.qual & 0x1F) {
                     case ARGUS_TYPE_IPV4: {
                        struct ArgusGeoLocationStruct *geo = NULL;

                        if (labeler->RaLabelGeoIPCity & ARGUS_SRC_ADDR)
                           if ((gir = GeoIP_record_by_ipnum (labeler->RaGeoIPv4CityObject, flow->ip_flow.ip_src)) != NULL) {
                              if ((geo = (struct ArgusGeoLocationStruct *)argus->dsrs[ARGUS_GEO_INDEX]) == NULL) {
                                 geo = (struct ArgusGeoLocationStruct *) ArgusCalloc(1, sizeof(*geo));
                                 geo->hdr.type = ARGUS_GEO_DSR;
                                 geo->hdr.argus_dsrvl8.len = (sizeof(*geo) + 3) / 4;

                                 argus->dsrs[ARGUS_GEO_INDEX] = &geo->hdr;
                                 argus->dsrindex |= (0x1 << ARGUS_GEO_INDEX);
                              }
                              geo->hdr.argus_dsrvl8.qual |= ARGUS_SRC_GEO;
                              geo->src.lat = gir->latitude;
                              geo->src.lon = gir->longitude;

                              ArgusPrintGeoIPRecord(parser, gir, label, len, _found, "scity=");
                              GeoIPRecord_delete(gir);
                              _found++;
                           }

                        if (labeler->RaLabelGeoIPCity & ARGUS_DST_ADDR)
                           if ((gir = GeoIP_record_by_ipnum (labeler->RaGeoIPv4CityObject, flow->ip_flow.ip_dst)) != NULL) {
                              if ((geo = (struct ArgusGeoLocationStruct *)argus->dsrs[ARGUS_GEO_INDEX]) == NULL) {
                                 geo = (struct ArgusGeoLocationStruct *) ArgusCalloc(1, sizeof(*geo));
                                 geo->hdr.type = ARGUS_GEO_DSR;
                                 geo->hdr.argus_dsrvl8.len = (sizeof(*geo) + 3) / 4;
                                 argus->dsrs[ARGUS_GEO_INDEX] = &geo->hdr;
                                 argus->dsrindex |= (0x1 << ARGUS_GEO_INDEX);
                              }
                              geo->hdr.argus_dsrvl8.qual |= ARGUS_DST_GEO;
                              geo->dst.lat = gir->latitude;
                              geo->dst.lon = gir->longitude;
                              ArgusPrintGeoIPRecord(parser, gir, label, len, _found, "dcity=");
                              GeoIPRecord_delete(gir);
                              _found++;
                           }

                        if (labeler->RaLabelGeoIPCity & ARGUS_INODE_ADDR) {
                           struct ArgusIcmpStruct *icmp = (void *)argus->dsrs[ARGUS_ICMP_INDEX];

                           if (icmp != NULL) {
                              if (icmp->hdr.argus_dsrvl8.qual & ARGUS_ICMP_MAPPED) {
                                 struct ArgusFlow *flow = (void *)argus->dsrs[ARGUS_FLOW_INDEX];

                                 if (flow != NULL) {
                                    switch (flow->hdr.subtype & 0x3F) {
                                       case ARGUS_FLOW_CLASSIC5TUPLE:
                                       case ARGUS_FLOW_LAYER_3_MATRIX: {
                                          switch (flow->hdr.argus_dsrvl8.qual & 0x1F) {
                                             case ARGUS_TYPE_IPV4:
                                                if ((gir = GeoIP_record_by_ipnum (labeler->RaGeoIPv4CityObject, icmp->osrcaddr)) != NULL) {
                                                   if ((geo = (struct ArgusGeoLocationStruct *)argus->dsrs[ARGUS_GEO_INDEX]) == NULL) {
                                                      geo = (struct ArgusGeoLocationStruct *) ArgusCalloc(1, sizeof(*geo));
                                                      geo->hdr.type = ARGUS_GEO_DSR;
                                                      geo->hdr.argus_dsrvl8.len = (sizeof(*geo) + 3) / 4;
                                                      argus->dsrs[ARGUS_GEO_INDEX] = &geo->hdr;
                                                      argus->dsrindex |= (0x1 << ARGUS_GEO_INDEX);
                                                   }
                                                   geo->hdr.argus_dsrvl8.qual |= ARGUS_INODE_GEO;
                                                   geo->inode.lat = gir->latitude;
                                                   geo->inode.lon = gir->longitude;
                                                   ArgusPrintGeoIPRecord(parser, gir, label, len, _found, "icity=");
                                                   GeoIPRecord_delete(gir);
                                                   _found++;
                                                }
                                                break;

                                             case ARGUS_TYPE_IPV6:
                                                break;
                                          }
                                          break;
                                       }

                                       default:
                                          break;
                                    }
                                 }
                              }
                           }
                        }
                        break;
                     }
                     case ARGUS_TYPE_IPV6: {
                        if (labeler->RaGeoIPv6CityObject != NULL) {
                           if (labeler->RaLabelGeoIPCity & ARGUS_SRC_ADDR) {
                              struct in6_addr saddr;
                              bcopy(flow->ipv6_flow.ip_src, saddr.s6_addr, sizeof(saddr));

                              if ((gir = GeoIP_record_by_ipnum_v6 (labeler->RaGeoIPv6CityObject, saddr)) != NULL) {
                                 ArgusPrintGeoIPRecord(parser, gir, label, len, _found, "scity=");
                                 GeoIPRecord_delete(gir);
                                 _found++;
                              }
                           }

                           if (labeler->RaLabelGeoIPCity & ARGUS_DST_ADDR) {
                              struct in6_addr daddr;
                              bcopy(flow->ipv6_flow.ip_dst, daddr.s6_addr, sizeof(daddr));

                              if ((gir = GeoIP_record_by_ipnum_v6 (labeler->RaGeoIPv6CityObject, daddr)) != NULL) {
                                 ArgusPrintGeoIPRecord(parser, gir, label, len, _found, "dcity=");
                                 GeoIPRecord_delete(gir);
                                 _found++;
                              }
                           }
                        }
                        break;
                     }
                  }
               }
            }
         }
      }
   }

   *found = _found;
   return 1;
}

#endif
