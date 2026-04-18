/*
 * IRC - Internet Relay Chat, ircd/ircd_geoip.c
 * Copyright (C) 2026 Cathexis Development
 *
 * GeoIP2 (MaxMindDB) integration — country, continent, and city lookups.
 * Legacy GeoIP (libGeoIP) has been removed. Only libmaxminddb (MMDB) is
 * supported. Requires GeoLite2-City.mmdb or GeoIP2-City.mmdb for full
 * data; GeoLite2-Country.mmdb provides country/continent only.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3, or (at your option)
 * any later version.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <string.h>

#include "config.h"
#include "client.h"
#include "ircd_geoip.h"
#include "ircd_features.h"
#include "ircd_string.h"
#include "ircd_log.h"
#include "res.h"
#include "s_debug.h"

#ifdef USE_MMDB
#include <maxminddb.h>

static MMDB_s mmdb;
static int    mmdb_loaded = 0;
#endif /* USE_MMDB */

/* -- Continent lookup table -- */

static const char continent_codes[7][3] = {
  "--", "AF", "AS", "EU", "NA", "OC", "SA"
};
static const char *continent_names[7] = {
  "N/A", "Africa", "Asia", "Europe",
  "North America", "Oceania", "South America"
};

const char *geoip_continent_name_by_code(const char *cc)
{
  int i;
  if (!cc) return continent_names[0];
  for (i = 0; i < 7; i++) {
    if (strncasecmp(cc, continent_codes[i], 2) == 0)
      return continent_names[i];
  }
  return continent_names[0];
}

/* -- Helper: extract UTF-8 string from MMDB entry -- */

#ifdef USE_MMDB
static void mmdb_get_str(MMDB_entry_s *entry, char *dst, size_t dstlen,
                          const char *key1, const char *key2, const char *key3)
{
  MMDB_entry_data_s data;
  int status;

  if (key3)
    status = MMDB_get_value(entry, &data, key1, key2, key3, NULL);
  else if (key2)
    status = MMDB_get_value(entry, &data, key1, key2, NULL);
  else
    status = MMDB_get_value(entry, &data, key1, NULL);

  if (status == MMDB_SUCCESS && data.has_data &&
      data.type == MMDB_DATA_TYPE_UTF8_STRING) {
    size_t len = data.data_size < (dstlen - 1) ? data.data_size : (dstlen - 1);
    memcpy(dst, data.utf8_string, len);
    dst[len] = '\0';
  }
}
#endif /* USE_MMDB */

/* -- Init / shutdown -- */

void geoip_init(void)
{
#ifdef USE_MMDB
  int status;

  if (mmdb_loaded) {
    MMDB_close(&mmdb);
    mmdb_loaded = 0;
  }

  if (!feature_bool(FEAT_GEOIP_ENABLE))
    return;

  status = MMDB_open(feature_str(FEAT_MMDB_FILE), MMDB_MODE_MMAP, &mmdb);
  if (status == MMDB_SUCCESS) {
    mmdb_loaded = 1;
    log_write(LS_SYSTEM, L_INFO, 0,
              "GeoIP: Loaded MaxMindDB %s (type: %s)",
              feature_str(FEAT_MMDB_FILE),
              mmdb.metadata.database_type);
  } else {
    log_write(LS_SYSTEM, L_ERROR, 0,
              "GeoIP: Failed to load %s: %s",
              feature_str(FEAT_MMDB_FILE), MMDB_strerror(status));
    if (status == MMDB_IO_ERROR)
      log_write(LS_SYSTEM, L_ERROR, 0,
                "GeoIP: IO error: %s", strerror(errno));
  }
#endif /* USE_MMDB */
}

/* -- Apply GeoIP data to a client -- */

void geoip_apply(struct Client *cptr)
{
#ifdef USE_MMDB
  MMDB_lookup_result_s result;
  int gai_error, mmdb_error;
#endif

  if (!feature_bool(FEAT_GEOIP_ENABLE) || !cptr)
    return;

  /* Set defaults */
  ircd_strncpy(cli_countrycode(cptr), "--", sizeof(cptr->cli_countrycode));
  ircd_strncpy(cli_countryname(cptr), "Unknown", sizeof(cptr->cli_countryname));
  ircd_strncpy(cli_continentcode(cptr), "--", sizeof(cptr->cli_continentcode));
  ircd_strncpy(cli_continentname(cptr), "Unknown", sizeof(cptr->cli_continentname));
  cli_city(cptr)[0] = '\0';

#ifdef USE_MMDB
  if (!mmdb_loaded)
    goto done;

  result = MMDB_lookup_string(&mmdb, ircd_ntoa(&cli_ip(cptr)),
                               &gai_error, &mmdb_error);

  if (gai_error != 0 || mmdb_error != MMDB_SUCCESS || !result.found_entry)
    goto done;

  /* Country */
  mmdb_get_str(&result.entry, cli_countrycode(cptr),
               sizeof(cptr->cli_countrycode),
               "country", "iso_code", NULL);
  mmdb_get_str(&result.entry, cli_countryname(cptr),
               sizeof(cptr->cli_countryname),
               "country", "names", "en");

  /* Continent */
  mmdb_get_str(&result.entry, cli_continentcode(cptr),
               sizeof(cptr->cli_continentcode),
               "continent", "code", NULL);
  mmdb_get_str(&result.entry, cli_continentname(cptr),
               sizeof(cptr->cli_continentname),
               "continent", "names", "en");

  /* City (available in GeoLite2-City / GeoIP2-City databases) */
  mmdb_get_str(&result.entry, cli_city(cptr),
               sizeof(cptr->cli_city),
               "city", "names", "en");

done:
#endif /* USE_MMDB */
  SetGeoIP(cptr);
}

/* -- Apply from MARK (S2S propagation) -- */

void geoip_apply_mark(struct Client *cptr, char *country,
                       char *continent, char *countryname)
{
  ircd_strncpy(cli_countrycode(cptr),
               country ? country : "--", sizeof(cptr->cli_countrycode));
  ircd_strncpy(cli_continentcode(cptr),
               continent ? continent : "--", sizeof(cptr->cli_continentcode));

  if (countryname)
    ircd_strncpy(cli_countryname(cptr), countryname,
                 sizeof(cptr->cli_countryname));
  else
    ircd_strncpy(cli_countryname(cptr), "Unknown",
                 sizeof(cptr->cli_countryname));

  ircd_strncpy(cli_continentname(cptr),
               (continent && strcmp(continent, "--"))
                 ? geoip_continent_name_by_code(continent)
                 : "Unknown",
               sizeof(cptr->cli_continentname));

  cli_city(cptr)[0] = '\0';
  SetGeoIP(cptr);
}

/* -- Feature handlers -- */

void geoip_handle_enable(void) { geoip_init(); }

void geoip_handle_mmdb_file(void)
{
#ifdef USE_MMDB
  if (mmdb_loaded) {
    MMDB_close(&mmdb);
    mmdb_loaded = 0;
  }
  geoip_init();
#endif
}

const char *geoip_libmmdb_version(void)
{
#ifdef USE_MMDB
  return MMDB_lib_version();
#else
  return "not compiled";
#endif
}
