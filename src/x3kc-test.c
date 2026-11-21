/* Standalone asserts for the Keycloak backend pieces; links only the files
 * under test, never the services.  Exit 0 when every assert holds. */
#undef NDEBUG
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "kcid.h"

int main(void)
{
    char c[23], u[37];
    assert(kcid_from_uuid("6ba7b810-9dad-11d1-80b4-00c04fd430c8", c) == 1);
    assert(strcmp(c, "a6e4EJ2tEdGAtADAT9QwyA") == 0);
    assert(kcid_to_uuid("a6e4EJ2tEdGAtADAT9QwyA", u) == 1);
    assert(strcmp(u, "6ba7b810-9dad-11d1-80b4-00c04fd430c8") == 0);
    assert(kcid_to_uuid("a6e4EJ2tEdGAtADAT9Qwy", u) == 0);     /* 21 chars */
    assert(kcid_to_uuid("a6e4EJ2tEdGAtADAT9Qwy!", u) == 0);    /* bad char */
    assert(kcid_to_uuid(NULL, u) == 0);
    puts("x3kc-test: ok");
    return 0;
}
