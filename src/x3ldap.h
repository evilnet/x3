#include "nickserv.h"
int ldap_do_init();

unsigned int ldap_check_auth(char *account, char *pass);

void ldap_close();
