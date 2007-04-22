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

#include "config.h"
#ifdef WITH_LDAP

#include <stdio.h>
#include <stdlib.h>
#include <ldap.h>

#include "conf.h"
#include "global.h"
#include "log.h"
#include "x3ldap.h"

extern struct nickserv_config nickserv_conf;


LDAP *ld = NULL;
int admin_bind = false;

int ldap_do_init()
{
   if(!nickserv_conf.ldap_enable)
     return false;
   /* TODO: check here for all required config options and exit() out if not present */
   //ld = ldap_init(nickserv_conf.ldap_host, nickserv_conf.ldap_port);

   //if(ld == NULL) {
   if(ldap_initialize(&ld, nickserv_conf.ldap_uri)) {
      log_module(MAIN_LOG, LOG_ERROR, "LDAP initilization failed!\n");
      exit(1);
   }
   ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &nickserv_conf.ldap_version);
   log_module(MAIN_LOG, LOG_INFO, "Success! ldap_init() was successfull in connecting to %s\n", nickserv_conf.ldap_uri);
   return true;
}


/* Try to auth someone. If theres problems, try reconnecting 
 * once every 10 seconds for 1 minute.
 * TODO: move this stuff to config file
 */
unsigned int ldap_do_bind( const char *dn, const char *pass)
{
   int q;

   int n = 0;
   while(1) {
      q = ldap_simple_bind_s(ld, dn, pass);
      if(q == LDAP_SUCCESS) {
           log_module(MAIN_LOG, LOG_DEBUG, "bind() successfull! You are bound as %s", dn);
           /* unbind now */
           return q;
      }
      else if(q == LDAP_INVALID_CREDENTIALS) {
        return q;
      }
      else {
        log_module(MAIN_LOG, LOG_ERROR, "Bind failed: %s/******  (%s)", dn, ldap_err2string(q));
        /* ldap_perror(ld, "ldap"); */
        ldap_do_init();
      }
      if(n++ > 1) {
         /* TODO: return to the user that this is a connection error and not a problem
          * with their password
          */
         log_module(MAIN_LOG, LOG_ERROR, "Failing to reconnect to ldap server. Auth failing.");
         return q;
      }
   }
   log_module(MAIN_LOG, LOG_ERROR, "ldap_do_bind falling off the end. this shouldnt happen");
   return q;
}
int ldap_do_admin_bind()
{
   int rc;
   if(!(nickserv_conf.ldap_admin_dn && *nickserv_conf.ldap_admin_dn && 
      nickserv_conf.ldap_admin_pass && *nickserv_conf.ldap_admin_pass)) {
       log_module(MAIN_LOG, LOG_ERROR, "Tried to admin bind, but no admin credentials configured in config file. ldap_admin_dn/ldap_admin_pass");
       return LDAP_OTHER; /* not configured to do this */
    }
    rc = ldap_do_bind(nickserv_conf.ldap_admin_dn, nickserv_conf.ldap_admin_pass);
    if(rc == LDAP_SUCCESS)
       admin_bind = true;
    return rc;
}


unsigned int ldap_check_auth( char *account, char *pass)
{
   char buff[MAXLEN];

   if(!nickserv_conf.ldap_enable)
     return LDAP_OTHER;

   memset(buff, 0, MAXLEN);
   snprintf(buff, sizeof(buff)-1, nickserv_conf.ldap_dn_fmt /*"uid=%s,ou=Users,dc=afternet,dc=org"*/, account);
   admin_bind = false;
   return ldap_do_bind(buff, pass);

}

int ldap_search_user(char *account, LDAPMessage **entry)
{

   char filter[MAXLEN+1];
   int rc;
   LDAPMessage *res;

   struct timeval timeout;

   memset(filter, 0, MAXLEN+1);
   snprintf(filter, MAXLEN, "%s=%s", nickserv_conf.ldap_field_account, account);
   /*
    Now we do a search;
    */
   timeout.tv_usec = 0;
   timeout.tv_sec  = nickserv_conf.ldap_timeout;
    if(!admin_bind && LDAP_SUCCESS != ( rc = ldap_do_admin_bind())) {
       log_module(MAIN_LOG, LOG_ERROR, "failed to bind as admin");
       return rc;
    }
   if( (rc = ldap_search_st(ld, nickserv_conf.ldap_base, LDAP_SCOPE_ONELEVEL, filter, NULL, 0, &timeout, &res)) != LDAP_SUCCESS) {
       log_module(MAIN_LOG, LOG_ERROR, "search failed: %s   %s: %s", nickserv_conf.ldap_base, filter, ldap_err2string(rc));
       return(rc);
   }
   log_module(MAIN_LOG, LOG_DEBUG, "Search successfull!  %s    %s\n", nickserv_conf.ldap_base, filter);
   if(ldap_count_entries(ld, res) != 1) {
      log_module(MAIN_LOG, LOG_DEBUG, "LDAP search got %d entries when looking for %s", ldap_count_entries(ld, res), account);
      return(LDAP_OTHER); /* Search was a success, but user not found.. */
   }
   log_module(MAIN_LOG, LOG_DEBUG, "LDAP search got %d entries", ldap_count_entries(ld, res));
   *entry = ldap_first_entry(ld, res);
   return(rc);
}

/* queries the ldap server for account..
 * if a single account match is found, 
 * email is allocated and set to the email address
 * and returns LDAP_SUCCESS. returns LDAP_OTHER if
 * 0 or 2+ entries are matched, or the proper ldap error
 * code for other errors.
 */ 
int ldap_get_user_info(char *account, char **email) 
{
    int rc;
    char **value;
    LDAPMessage *entry, *res;
    if(email)
      *email = NULL;
    if( (rc = ldap_search_user(account, &res)) == LDAP_SUCCESS) {
        entry = ldap_first_entry(ld, res);
        value = ldap_get_values(ld, entry, nickserv_conf.ldap_field_email);
        if(!value) {
           return(LDAP_OTHER);
        }
        if(email)
          *email = strdup(value[0]);
        log_module(MAIN_LOG, LOG_DEBUG, "%s: %s\n", nickserv_conf.ldap_field_email, value[0]);
        /*
        value = ldap_get_values(ld, entry, "description");
        log_module(MAIN_LOG, LOG_DEBUG, "Description: %s\n", value[0]);
        value = ldap_get_values(ld, entry, "userPassword");
        log_module(MAIN_LOG, LOG_DEBUG, "pass: %s\n", value ? value[0] : "error");
        */
    }
    return(rc);
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


/********* base64 stuff ***********/

unsigned char *pack(const char *str, unsigned int *len)
{
    int nibbleshift = 4;
    int first = 1;
    char *v;
    static unsigned char buf[MAXLEN+1];
    int outputpos = -1;

    memset(buf, 0, MAXLEN+1);
    v = (char *)str;
    while(*v) {
        char n = *(v++);

        if((n >= '0') && (n <= '9')) {
            n -= '0';
        } else if ((n >= 'A') && (n <= 'F')) {
                n -= ('A' - 10);
        } else if ((n >= 'a') && (n <= 'f')) {
                n -= ('a' - 10);
        } else {
                printf("pack type H: illegal hex digit %c", n);
                n = 0;
        }

        if (first--) {
                buf[++outputpos] = 0;
        } else {
                first = 1;
        }

        buf[outputpos] |= (n << nibbleshift);
        nibbleshift = (nibbleshift + 4) & 7;
    }
    *len = outputpos+1;
    return(buf);
}


/* from php5 sources */
static char base64_table[] =
        { 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
          'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
          'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
          'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
          '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/', '\0'
        };
static char base64_pad = '=';

char *base64_encode(const unsigned  char *str, int length, int *ret_length)
{
    const unsigned char *current = str;
    char *p;
    char *result;

    if ((length + 2) < 0 || ((length + 2) / 3) >= (1 << (sizeof(int) * 8 - 2))) {
        if (ret_length != NULL) {
            *ret_length = 0;
        }
        return NULL;
    }

    result = (char *)calloc(((length + 2) / 3) * 4, sizeof(char));
    p = result;

    while (length > 2) { /* keep going until we have less than 24 bits */
        *p++ = base64_table[current[0] >> 2];
        *p++ = base64_table[((current[0] & 0x03) << 4) + (current[1] >> 4)];
        *p++ = base64_table[((current[1] & 0x0f) << 2) + (current[2] >> 6)];
        *p++ = base64_table[current[2] & 0x3f];

        current += 3;
        length -= 3; /* we just handle 3 octets of data */
    }

    /* now deal with the tail end of things */
    if (length != 0) {
        *p++ = base64_table[current[0] >> 2];
        if (length > 1) {
            *p++ = base64_table[((current[0] & 0x03) << 4) + (current[1] >> 4)];
            *p++ = base64_table[(current[1] & 0x0f) << 2];
            *p++ = base64_pad;
        } else {
            *p++ = base64_table[(current[0] & 0x03) << 4];
            *p++ = base64_pad;
            *p++ = base64_pad;
        }
    }
    if (ret_length != NULL) {
        *ret_length = (int)(p - result);
    }
    *p = '\0';
    return result;
}


char **make_object_vals()
{
    unsigned int y;
    static char **object_vals = NULL;

    if(object_vals)
       free(object_vals);

    object_vals = malloc(sizeof( *object_vals ) * nickserv_conf.ldap_object_classes->used);

    for(y = 0; y < nickserv_conf.ldap_object_classes->used; y++) {
        object_vals[y] = nickserv_conf.ldap_object_classes->list[y];
    }
    object_vals[y] = NULL;
    return object_vals;
}

char *make_password(const char *crypted)
{
       char *base64pass;
       unsigned char *packed;
       unsigned int len;
       char *passbuf;

       packed = pack(crypted, &len);
       base64pass = base64_encode(packed, len, NULL);
       passbuf = malloc(strlen(base64pass) + 1 + 5);
       strcpy(passbuf, "{MD5}");
       strcat(passbuf, base64pass);
       //log_module(MAIN_LOG, LOG_DEBUG, "Encoded password is: '%s'", passbuf);
       free(base64pass);
       return passbuf;

}

LDAPMod **make_mods_add(const char *account, const char *password, const char *email, int *num_mods_ret)
{
    static char *account_vals[] = { NULL, NULL };
    static char *password_vals[] = { NULL, NULL };
    static char *email_vals[] = { NULL, NULL };
    int num_mods = 3;
    int i;
    /* TODO: take this from nickserv_conf.ldap_add_objects */
    LDAPMod **mods;
    static char **object_vals;
    object_vals = make_object_vals();

    account_vals[0] = (char *) account;
    password_vals[0] = (char *) password;
    email_vals[0] = (char *) email;

    if(!(nickserv_conf.ldap_field_account && *nickserv_conf.ldap_field_account))
       return 0; /* account required */
    if(!(nickserv_conf.ldap_field_password && *nickserv_conf.ldap_field_password))
       return 0; /* password required */
    if(email && *email && nickserv_conf.ldap_field_email && *nickserv_conf.ldap_field_email)
       num_mods++;

    mods = ( LDAPMod ** ) malloc(( num_mods + 1 ) * sizeof( LDAPMod * ));
    for( i = 0; i < num_mods; i++) {
      mods[i] = (LDAPMod *) malloc(sizeof(LDAPMod));
      memset(mods[i], 0, sizeof(LDAPMod));
    }

    mods[0]->mod_op = LDAP_MOD_ADD;
    mods[0]->mod_type = strdup("objectclass");
    mods[0]->mod_values = object_vals;

    mods[1]->mod_op = LDAP_MOD_ADD;
    mods[1]->mod_type = strdup(nickserv_conf.ldap_field_account);
    mods[1]->mod_values = account_vals;

    mods[2]->mod_op = LDAP_MOD_ADD;
    mods[2]->mod_type = strdup(nickserv_conf.ldap_field_password);
    mods[2]->mod_values = password_vals;

    if(nickserv_conf.ldap_field_email && *nickserv_conf.ldap_field_email && email && *email) {
        mods[3]->mod_op = LDAP_MOD_ADD;
        mods[3]->mod_type = strdup(nickserv_conf.ldap_field_email);
        mods[3]->mod_values = email_vals;
        mods[4] = NULL;
    }
    else
       mods[3] = NULL;
    *num_mods_ret = num_mods;
    return mods;
}

int ldap_do_add(const char *account, const char *crypted, const char *email)
{
    char newdn[MAXLEN];
    LDAPMod **mods;
    int rc, i;
    int num_mods;
    char *passbuf;
    
    if(!admin_bind && LDAP_SUCCESS != ( rc = ldap_do_admin_bind())) {
       log_module(MAIN_LOG, LOG_ERROR, "failed to bind as admin");
       return rc;
    }
    
    passbuf = make_password(crypted);
    snprintf(newdn, MAXLEN-1, nickserv_conf.ldap_dn_fmt, account);
    mods = make_mods_add(account, passbuf, email, &num_mods);
    if(!mods) {
       log_module(MAIN_LOG, LOG_ERROR, "Error building mods for ldap_add");
       return LDAP_OTHER;
    }
    rc = ldap_add_ext_s(ld, newdn, mods, NULL, NULL);
    if(rc != LDAP_SUCCESS && rc!= LDAP_ALREADY_EXISTS) {
       log_module(MAIN_LOG, LOG_ERROR, "Error adding ldap account: %s -- %s", account, ldap_err2string(rc));
    //   return rc;
    }
    //ldap_unbind_s(ld);
    for(i = 0; i < num_mods; i++) {
       free(mods[i]->mod_type);
       free(mods[i]);
    }
    free(mods);
    free(passbuf);
    return rc;
}

int ldap_delete_account(char *account)
{
    char dn[MAXLEN];
    int rc;

    if(!admin_bind && LDAP_SUCCESS != ( rc = ldap_do_admin_bind())) {
       log_module(MAIN_LOG, LOG_ERROR, "failed to bind as admin");
       return rc;
    }

    memset(dn, 0, MAXLEN);
    snprintf(dn, MAXLEN-1, nickserv_conf.ldap_dn_fmt, account);
    return(ldap_delete_s(ld, dn));
}

int ldap_rename_account(char *oldaccount, char *newaccount)
{
    char dn[MAXLEN], newdn[MAXLEN];
    int rc;

    if(!admin_bind && LDAP_SUCCESS != ( rc = ldap_do_admin_bind())) {
       log_module(MAIN_LOG, LOG_ERROR, "failed to bind as admin");
       return rc;
    }

    memset(dn, 0, MAXLEN);
    memset(newdn, 0, MAXLEN);
    snprintf(dn, MAXLEN-1, nickserv_conf.ldap_dn_fmt, oldaccount);
    strcat(newdn, nickserv_conf.ldap_field_account);
    strcat(newdn, "=");
    strcat(newdn, newaccount);
    rc = ldap_modrdn2_s(ld, dn, newdn, true);
    if(rc != LDAP_SUCCESS) {
       log_module(MAIN_LOG, LOG_ERROR, "Error modifying ldap account: %s -- %s", oldaccount, ldap_err2string(rc));
       //return rc;
    }
    return rc;
    
}

LDAPMod **make_mods_modify(const char *password, const char *email, int *num_mods_ret)
{
    static char *password_vals[] = { NULL, NULL };
    static char *email_vals[] = { NULL, NULL };
    int num_mods = 0;
    int i;
    /* TODO: take this from nickserv_conf.ldap_add_objects */
    LDAPMod **mods;

    password_vals[0] = (char *) password;
    email_vals[0] = (char *) email;

    if(!(nickserv_conf.ldap_field_password && *nickserv_conf.ldap_field_password))
       return 0; /* password required */
    /*
    if(email && *email && nickserv_conf.ldap_field_email && *nickserv_conf.ldap_field_email)
       num_mods++;
    */
    if(password)
       num_mods++;
    if(email)
       num_mods++;

    mods = ( LDAPMod ** ) malloc(( num_mods + 1 ) * sizeof( LDAPMod * ));
    for( i = 0; i < num_mods; i++) {
      mods[i] = (LDAPMod *) malloc(sizeof(LDAPMod));
      memset(mods[i], 0, sizeof(LDAPMod));
    }

    i = 0;
    if(nickserv_conf.ldap_field_password && *nickserv_conf.ldap_field_password && 
       password) {
        mods[i]->mod_op = LDAP_MOD_REPLACE;
        mods[i]->mod_type = strdup(nickserv_conf.ldap_field_password);
        mods[i]->mod_values = password_vals;
        i++;
    }

    if(nickserv_conf.ldap_field_email && *nickserv_conf.ldap_field_email && email) {
        mods[i]->mod_op = LDAP_MOD_REPLACE;
        mods[i]->mod_type = strdup(nickserv_conf.ldap_field_email);
        mods[i]->mod_values = email_vals;
        i++;
    }
    mods[i] = NULL;
    *num_mods_ret = num_mods;
    return mods;
}


/* Save email or password to server
 *
 * password - UNENCRYPTED password. This function encrypts if libs are available
 * email    - email address
 *
 * NULL to make no change
 */
int ldap_do_modify(const char *account, const char *password, const char *email)
{
    char dn[MAXLEN];
    LDAPMod **mods;
    int rc, i;
    int num_mods;
    char *passbuf = NULL;
    
    if(!admin_bind && LDAP_SUCCESS != ( rc = ldap_do_admin_bind())) {
       log_module(MAIN_LOG, LOG_ERROR, "failed to bind as admin");
       return rc;
    }

    if(password) {
       passbuf = make_password(password);
    }
    
    snprintf(dn, MAXLEN-1, nickserv_conf.ldap_dn_fmt, account);
    mods = make_mods_modify(passbuf, email, &num_mods);
    if(!mods) {
       log_module(MAIN_LOG, LOG_ERROR, "Error building mods for ldap_do_modify");
       return LDAP_OTHER;
    }
    rc = ldap_modify_s(ld, dn, mods);
    if(rc != LDAP_SUCCESS) {
       log_module(MAIN_LOG, LOG_ERROR, "Error modifying ldap account: %s -- %s", account, ldap_err2string(rc));
    //   return rc;
    }
    for(i = 0; i < num_mods; i++) {
       free(mods[i]->mod_type);
       free(mods[i]);
    }
    free(mods);
    if(passbuf)
      free(passbuf);
    return rc;
}

LDAPMod **make_mods_group(const char *account, int operation, int *num_mods_ret)
{
    static char *uid_vals[] = { NULL, NULL };
    int num_mods = 1;
    int i;
    /* TODO: take this from nickserv_conf.ldap_add_objects */
    LDAPMod **mods;

    uid_vals[0] = (char *) account;

    if(!(nickserv_conf.ldap_field_group_member && *nickserv_conf.ldap_field_group_member))
       return 0; /* password required */

    mods = ( LDAPMod ** ) malloc(( num_mods + 1 ) * sizeof( LDAPMod * ));
    for( i = 0; i < num_mods; i++) {
      mods[i] = (LDAPMod *) malloc(sizeof(LDAPMod));
      memset(mods[i], 0, sizeof(LDAPMod));
    }

    i = 0;
    mods[i]->mod_op = operation;
    mods[i]->mod_type = strdup(nickserv_conf.ldap_field_group_member);
    mods[i]->mod_values = uid_vals;
    i++;
    mods[i] = NULL;
    *num_mods_ret = num_mods;
    return mods;
}


int ldap_add2group(char *account, const char *group)
{
    LDAPMod **mods;
    int num_mods;
    int rc, i;

    if(!admin_bind && LDAP_SUCCESS != ( rc = ldap_do_admin_bind())) {
       log_module(MAIN_LOG, LOG_ERROR, "failed to bind as admin");
       return rc;
    }
    mods = make_mods_group(account, LDAP_MOD_ADD, &num_mods);
    if(!mods) {
       log_module(MAIN_LOG, LOG_ERROR, "Error building mods for add2group");
       return LDAP_OTHER;
    }
    rc = ldap_modify_s(ld, group, mods);
    if(rc != LDAP_SUCCESS && rc != LDAP_ALREADY_EXISTS) {
       log_module(MAIN_LOG, LOG_ERROR, "Error adding %s to group %s: %s", account, group, ldap_err2string(rc));
       return rc;
    }
    for(i = 0; i < num_mods; i++) {
       free(mods[i]->mod_type);
       free(mods[i]);
    }
    free(mods);
    return rc;
}

int ldap_delfromgroup(char *account, const char *group)
{
    LDAPMod **mods;
    int num_mods;
    int rc, i;

    if(!admin_bind && LDAP_SUCCESS != ( rc = ldap_do_admin_bind())) {
       log_module(MAIN_LOG, LOG_ERROR, "failed to bind as admin");
       return rc;
    }
    mods = make_mods_group(account, LDAP_MOD_DELETE, &num_mods);
    if(!mods) {
       log_module(MAIN_LOG, LOG_ERROR, "Error building mods for delfromgroup");
       return LDAP_OTHER;
    }
    rc = ldap_modify_s(ld, group, mods);
    if(rc != LDAP_SUCCESS && rc != LDAP_NO_SUCH_ATTRIBUTE) {
       log_module(MAIN_LOG, LOG_ERROR, "Error removing %s from group %s: %s", account, group, ldap_err2string(rc));
       return rc;
    }
    for(i = 0; i < num_mods; i++) {
       free(mods[i]->mod_type);
       free(mods[i]);
    }
    free(mods);
    return rc;
}


void ldap_close()
{
   admin_bind = false;
   ldap_unbind(ld);
}

#endif
