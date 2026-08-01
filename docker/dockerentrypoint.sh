#!/bin/bash

# X3 Docker Entrypoint
# Reads x3.conf-dist, replaces all %VARIABLE% placeholders with environment
# variable values, and writes out x3.conf

BASECONFDIST=/x3/x3src/docker/x3.conf-dist
BASECONF=/x3/data/x3.conf

# Only generate config if it doesn't already exist
if [ -f "$BASECONF" ]; then
    echo "Found existing config at $BASECONF, skipping generation"
else
    echo "No existing config found, generating from template..."

    # Set defaults for required variables (can be overridden by environment)
    : "${X3_GENERAL_NAME:=x3.network}"
    : "${X3_GENERAL_BIND_ADDRESS:=127.0.0.1}"
    : "${X3_GENERAL_DESCRIPTION:=Network Services}"
    : "${X3_GENERAL_DOMAIN:=example.com}"
    : "${X3_GENERAL_NUMERIC:=199}"
    : "${X3_UPLINK_ADDRESS:=127.0.0.1}"
    : "${X3_UPLINK_PORT:=8888}"
    : "${X3_UPLINK_PASSWORD:=changeme}"

    # Server block
    # 8 = Nefarious 1.3.x; 9 = Nefarious 2.0.x (nefarious2) — must match your ircd.
    : "${X3_SERVER_TYPE:=8}"
    : "${X3_HIDDEN_HOST_TYPE:=1}"
    # MUST match the ircd's HOST_HIDING_KEY* F:lines; change in production —
    # stock keys make style-2 cloaks predictable.
    : "${X3_HIDDEN_HOST_KEY1:=45432}"
    : "${X3_HIDDEN_HOST_KEY2:=76934}"
    : "${X3_HIDDEN_HOST_KEY3:=98336}"
    : "${X3_HIDDEN_HOST_PREFIX:=NETWORK}"

    # OpServ clone-G-line threshold (untrusted_max).  Default 6 (stock).
    # 0 disables it — testbeds set X3_UNTRUSTED_MAX=0 in .env.local so harness
    # connection volume from a single host isn't auto-G-lined.
    : "${X3_UNTRUSTED_MAX:=6}"

    # NickServ (AuthServ) defaults
    : "${X3_NICKSERV_NICK:=AuthServ}"
    : "${X3_DEFAULT_MAXLOGINS:=3}"
    : "${X3_HARD_MAXLOGINS:=10}"
    : "${X3_AUTO_OPER:=+oxwgs}"
    : "${X3_AUTO_OPER_PRIVS:=CHAN_LIMIT SHOW_INVIS SHOW_ALL_INVIS KILL LOCAL_KILL REHASH RESTART DIE JUPE LOCAL_JUPE OPMODE WHOX SEE_CHAN PROPAGATE DISPLAY SEE_OPERS WIDE_GLINE FORCE_OPMODE REMOTEREHASH CHECK SEE_SECRET_CHAN WIDE_SHUN WIDE_ZLINE LIST_CHAN}"
    : "${X3_PASSWD_MIN_LENGTH:=4}"
    : "${X3_PASSWD_MIN_DIGITS:=0}"
    : "${X3_PASSWD_MIN_UPPER:=0}"
    : "${X3_PASSWD_MIN_LOWER:=0}"
    : "${X3_EMAIL_ENABLED:=0}"
    : "${X3_EMAIL_REQUIRED:=0}"
    : "${X3_COOKIE_TIMEOUT:=2d}"
    : "${X3_ACCOUNTS_PER_EMAIL:=1}"
    # Derived from X3_GENERAL_DOMAIN (set above) unless overridden.
    : "${X3_TITLEHOST_SUFFIX:=${X3_GENERAL_DOMAIN}}"

    # LDAP defaults (disabled unless overridden)
    : "${X3_LDAP_ENABLE:=0}"
    : "${X3_LDAP_WRITEBACK:=0}"
    : "${X3_LDAP_URI:=ldap://localhost:389}"
    : "${X3_LDAP_BASE:=ou=users,dc=example,dc=net}"
    : "${X3_LDAP_DN_FMT:=uid=%s,ou=users,dc=example,dc=net}"
    : "${X3_LDAP_ADMIN_DN:=cn=admin,dc=example,dc=net}"
    : "${X3_LDAP_ADMIN_PASS:=changeme}"
    : "${X3_LDAP_FIELD_ACCOUNT:=uid}"
    : "${X3_LDAP_FIELD_PASSWORD:=userPassword}"
    : "${X3_LDAP_FIELD_EMAIL:=mail}"
    : "${X3_LDAP_FIELD_OSLEVEL:=X3AccountLevel}"
    : "${X3_LDAP_FILTER:=(objectClass=inetOrgPerson)}"
    : "${X3_LDAP_AUTOCREATE:=1}"
    : "${X3_LDAP_TIMEOUT:=10}"

    # Copy the template to the output location
    cp "$BASECONFDIST" "$BASECONF"

    # Find all %VARIABLE% placeholders in the config and substitute them
    # with corresponding environment variable values
    grep -oE '%[A-Za-z_][A-Za-z0-9_]*%' "$BASECONF" | sort -u | while read -r placeholder; do
        # Extract variable name (remove the % signs)
        varname="${placeholder:1:-1}"

        # Get the value from environment (indirect expansion)
        value="${!varname}"

        # Only substitute if the variable is set
        if [ -n "$value" ]; then
            # Escape for use as a sed replacement with '|' as the s///
            # delimiter: backslash FIRST (so the escapes we add next are not
            # themselves re-escaped), then '&' (whole-match backreference)
            # and the '|' delimiter itself.  '/' needs no escaping here.
            escaped_value=$(printf '%s\n' "$value" | sed -e 's/\\/\\\\/g' -e 's/&/\\&/g' -e 's/|/\\|/g')
            sed -i "s|${placeholder}|${escaped_value}|g" "$BASECONF"
        else
            echo "Warning: No value set for ${varname}, leaving ${placeholder} unchanged"
        fi
    done

    echo "Generated $BASECONF from template"
fi

# Run the command passed to docker (CMD from Dockerfile)
exec "$@"
