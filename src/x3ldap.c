/* x3ldap.c - LDAP functionality for x3, by Rubin
 * Copyright 2002-2007 x3 Development Team
 *
 * This file is part of x3.
 *
 * x3 is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with srvx; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA.
 *
 *
 * TODO:
 *   * get queries working in static existance, so i understand how it works
 *   * get ldap enabled in ./configure
 *   * x3.conf settings to enable/configure its use
 *   * generic functions to enable ldap
 *   * nickserv.c work to use said functions.
 */

#ifdef WITH_LDAP

#include <stdio.h>
#include <stdlib.h>
#include <ldap.h>
//#include <sys/select.h>

#include "conf.h"
#include "config.h"
#include "global.h"
#include "log.h"
#include "x3ldap.h"

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif
#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif


/* char dn[] = "uid=%s,ou=Users,dc=afternet,dc=org";
char password[] = "xxxxxxx";
char base[] = "ou=Users,dc=afternet,dc=org";
int ldap_version = 3;
*/
extern struct nickserv_config nickserv_conf;


LDAP *ld = NULL;

int ldap_do_init()
{
   /* TODO: check here for all required config options and exit() out if not present */
   ld = ldap_init(nickserv_conf.ldap_host, nickserv_conf.ldap_port);
   if(ld == NULL) {
      log_module(MAIN_LOG, LOG_ERROR, "LDAP initilization failed!\n");
      exit(1);
   }
   ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &nickserv_conf.ldap_version);
   log_module(MAIN_LOG, LOG_INFO, "Success! ldap_init() was successfull in connecting to %s port %d\n", nickserv_conf.ldap_host, nickserv_conf.ldap_port );
   return true;
}

/* Try to auth someone. If theres problems, try reconnecting 
 * once every 10 seconds for 1 minute.
 * TODO: move this stuff to config file
 */
unsigned int ldap_check_auth( char *account, char *pass)
{
   char buff[MAXLEN];
   int q;

   memset(buff, 0, MAXLEN);
   snprintf(buff, sizeof(buff)-1, nickserv_conf.ldap_dn_fmt /*"uid=%s,ou=Users,dc=afternet,dc=org"*/, account);
   int n = 0;
   while(1) {
      q = ldap_simple_bind_s(ld, buff, pass);
      if(q == LDAP_SUCCESS) {
         return true;
      }
      else if(q == LDAP_INVALID_CREDENTIALS) {
        return false;
      }
      else {
        log_module(MAIN_LOG, LOG_ERROR, "Bind failed: %s/******  (%d)\n", buff, q);
        ldap_perror(ld, "ldap");
        /* Re-init to re-connect to ldap server if thats the problem */
        sleep(10);
        ldap_do_init(nickserv_conf);
      }
      if(n++ > 6) {
         log_module(MAIN_LOG, LOG_ERROR, "Failing to reconnect to ldap server. Dieing.");
         exit(1);
      }
   }
   log_module(MAIN_LOG, LOG_DEBUG, "bind() successfull! You are bound as %s\n", buff);
   return true;

}

#ifdef notdef /* not used yet - will be used to pull email etc out of ldap */
LDAPMessage ldap_search_user(char uid)
{

   char filter[] = "cn=admin";

   struct timeval timeout;
   /*
    Now we do a search;
    */
   timeout.tv_usec = 0;
   timeout.tv_sec  = 5;
   if( ldap_search_st(ld, base, LDAP_SCOPE_ONELEVEL, filter, NULL, 0, &timeout, &res) != LDAP_SUCCESS) {
       log_module(MAIN_LOG, LOG_ERROR, "search failed: %s   %s\n", base, filter);
       exit(1);
   }
   log_module(MAIN_LOG, LOG_DEBUG, "Search successfull!  %s    %s\n", base, filter);
   log_module(MAIN_LOG, LOG_DEBUG, "Got %d entries\n", ldap_count_entries(ld, res));
   {
      LDAPMessage *entry;
      char **value;
      entry = ldap_first_entry(ld, res);
      value = ldap_get_values(ld, entry, "cn");
      log_module(MAIN_LOG, LOG_DEBUG, "cn: %s\n", value[0]);
      value = ldap_get_values(ld, entry, "description");
      log_module(MAIN_LOG, LOG_DEBUG, "Description: %s\n", value[0]);
      value = ldap_get_values(ld, entry, "userPassword");
      log_module(MAIN_LOG, LOG_DEBUG, "pass: %s\n", value ? value[0] : "error");
   }
   /*
   ldap_result();
   ldap_first_entry();
   ldap_first_attribute();
   for(;;) {
      ldap_get_values();
      ldap_next_attribute();
   }

   ldap_parse_result();

   ldap_unbind_ext();

   */
   /* get errors with ldap_err2string(); */
}

#endif

void ldap_close()
{
   ldap_unbind(ld);
}

#endif
