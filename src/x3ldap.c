/*
 *
 * LDAP functionality for x3, by Rubin
 *
 * TODO:
 *   * get queries working in static existance, so i understand how it works
 *   * get ldap enabled in ./configure
 *   * x3.conf settings to enable/configure its use
 *   * generic functions to enable ldap
 *   * nickserv.c work to use said functions.
 */

#include <stdio.h>
#include <stdlib.h>
#include <ldap.h>
//#include <sys/select.h>

#include "conf.h"
#include "config.h"
#include "global.h"
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

#ifdef WITH_LDAP

/* char dn[] = "uid=%s,ou=Users,dc=afternet,dc=org";
char password[] = "xxxxxxx";
char base[] = "ou=Users,dc=afternet,dc=org";
int ldap_version = 3;
*/
extern struct nickserv_config nickserv_conf;


/* TODO: change all these printfs to proper debug statements */

LDAP *ld = NULL;

int ldap_do_init()
{
   /* TODO: check here for all required config options and exit() out if not present */
   ld = ldap_init(nickserv_conf.ldap_host, nickserv_conf.ldap_port);
   if(ld == NULL) {
      printf("Failed!\n");
      exit(1);
   }
   ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &nickserv_conf.ldap_version);
   printf("Success! ldap_init() was successfull in connecting to %s port %d\n", nickserv_conf.ldap_host, nickserv_conf.ldap_port );
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
        printf("Bind failed: %s/******  (%d)\n", buff, q);
        ldap_perror(ld, "ldap");
        /* Re-init to re-connect to ldap server if thats the problem */
        sleep(10);
        ldap_do_init(nickserv_conf);
      }
      if(n++ > 6) {
         printf("Failing to reconnect to ldap server. Dieing.");
         exit(1);
      }
   }
   printf("bind() successfull! You are bound as %s\n", buff);
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
       printf("search failed: %s   %s\n", base, filter);
       exit(1);
   }
   printf("Search successfull!  %s    %s\n", base, filter);
   printf("Got %d entries\n", ldap_count_entries(ld, res));
   {
      LDAPMessage *entry;
      char **value;
      entry = ldap_first_entry(ld, res);
      value = ldap_get_values(ld, entry, "cn");
      printf("cn: %s\n", value[0]);
      value = ldap_get_values(ld, entry, "description");
      printf("Description: %s\n", value[0]);
      value = ldap_get_values(ld, entry, "userPassword");
      printf("pass: %s\n", value ? value[0] : "error");
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
