# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

X3 is a complete set of IRC services for Nefarious IRCu P10 protocol networks, based on srvx. It provides ChanServ, NickServ (AuthServ), OpServ, HelpServ, Global, MemoServ, and SpamServ functionality.

## Build Commands

```bash
# Standard build (native)
./configure --prefix=/path/to/install --enable-debug
make
make install

# Configure with optional modules
./configure --prefix=/path/to/install --enable-modules=memoserv,helpserv,snoop

# Run in foreground with debug output
./x3 -fd

# Run as daemon (default)
./x3
```

## Build Dependencies

- GNU Autotools (autoconf, automake, flex, byacc)
- Optional: libldap for LDAP authentication, libtre for regex, GeoIP

## Docker

The `Dockerfile` builds X3 on Debian 12 with modules enabled (snoop, memoserv, helpserv). It runs as non-root user (UID/GID 1234).

### Two Configuration Methods

**Option 1: Environment Variables (simple)**

Pass environment variables and let the entrypoint generate config from the template:
- `docker/x3.conf-dist` - Config template with `%VARIABLE%` placeholders
- `docker/dockerentrypoint.sh` - Substitutes environment variables at startup

Key environment variables:
- `X3_UPLINK_ADDRESS`, `X3_UPLINK_PORT`, `X3_UPLINK_PASSWORD` - IRC server connection
- `X3_GENERAL_NAME`, `X3_GENERAL_NUMERIC`, `X3_GENERAL_DOMAIN` - Service identity
- `X3_LDAP_*` - LDAP authentication settings

**Option 2: Volume Mount (full control)**

Mount your own data directory containing a complete `x3.conf`:
```
-v /path/to/data:/x3/data
```

The entrypoint checks if `/x3/data/x3.conf` exists before generating one. If you provide your own config, it will be used as-is and environment variables are ignored.

## Architecture

### Core Services (src/)
- `nickserv.c` - Authentication service (AuthServ/NickServ) - account registration, login, password management
- `chanserv.c` - Channel service (X3/ChanServ) - channel registration, access control, settings
- `opserv.c` - Operator service (O3/OpServ) - network administration, glines, clone detection
- `global.c` - Network-wide announcements
- `spamserv.c` - Spam/flood protection

### Optional Modules (src/mod-*.c)
- `mod-memoserv.c` - User-to-user messaging
- `mod-helpserv.c` - Help queue management for support channels
- `mod-snoop.c` - Connection/join/part monitoring
- `mod-sockcheck.c` - Open proxy detection
- `mod-blacklist.c` - DNS blacklist checking

### Infrastructure
- `proto-p10.c` - Nefarious/ircu P10 protocol implementation
- `saxdb.c` - Database serialization (flat file format)
- `modcmd.c` - Command registration and routing
- `ioset*.c` - I/O multiplexing (select/epoll/kevent)

### Configuration
- `x3.conf.example` - Comprehensive example config with documentation

### Data Storage
- `x3.db` - Main database file (saxdb format, human-readable)
- Data is stored in a flat text format; can be hand-edited when X3 is stopped

## Key Configuration Sections

The config file uses a custom format (not JSON/YAML). Key sections:
- `"uplinks"` - IRC server connection details
- `"server"` - Service identity (hostname, numeric, network name)
- `"services"` - Bot nicknames and per-service settings
- `"modules"` - Optional module configuration
- `"dbs"` - Database file locations
- `"logs"` - Logging destinations

## Protocol Notes

X3 speaks the Undernet P10 protocol with Nefarious extensions. The `"server"."type"` setting must match your IRCd version:
- Type 8: Nefarious 1.3.x (legacy)
- Type 9: Nefarious 2.0.x (current)

## Testing

```bash
# Run from build directory after configure
./x3 -fd -c x3.conf
```

Connect to the IRC server and interact with the service bots (AuthServ, X3, O3, etc.).
