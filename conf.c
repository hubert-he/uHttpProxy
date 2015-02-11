/* Parses the configuration file and sets up the config_s structure for
 * use by the application.  This file replaces the old grammar.y and
 * scanner.l files.  It takes up less space and _I_ think is easier to
 * add new directives to.  Who knows if I'm right though.
 */

#include "conf.h"

struct config_s config; // primary config variable

int load_http_proxy_config (struct config_s *conf)
{
	config.idletimeout = (60 * 5);
  return 0;
}

