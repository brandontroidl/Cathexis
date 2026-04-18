/** @file ircd_geoip.h
 * @brief GeoIP2 (MaxMindDB) routine definitions.
 * Legacy libGeoIP support removed in Cathexis 1.4.0.
 */
#ifndef INCLUDED_ircd_geoip_h
#define INCLUDED_ircd_geoip_h

#include "client.h"

extern void geoip_init(void);
extern void geoip_apply(struct Client* cptr);
extern void geoip_apply_mark(struct Client* cptr, char* country, char* continent, char* countryname);
extern void geoip_handle_enable(void);
extern void geoip_handle_mmdb_file(void);
extern const char* geoip_continent_name_by_code(const char* cc);
extern const char* geoip_libmmdb_version(void);

#endif /* INCLUDED_ircd_geoip_h */
