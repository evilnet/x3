#!/bin/bash

# X3 Docker Entrypoint
# Reads x3.conf-dist, replaces all %VARIABLE% placeholders with environment
# variable values, and writes out x3.conf

BASECONFDIST=/x3/x3src/docker/x3.conf-dist
BASECONF=/x3/data/x3.conf

# Copy .help files and templates from /x3/share/x3 to /x3/data if they don't exist
echo "Checking for .help files in /x3/data..."
if [ ! -f /x3/data/chanserv.help ]; then
    echo "Copying .help files from /x3/share/x3 to /x3/data..."
    cp /x3/share/x3/*.help /x3/data/ 2>/dev/null || true
fi

if [ ! -f /x3/data/modpython.py ]; then
    echo "Copying modpython.py to /x3/data..."
    cp /x3/share/x3/modpython.py /x3/data/ 2>/dev/null || true
fi

if [ ! -d /x3/data/plugins ]; then
    echo "Copying plugins directory to /x3/data..."
    cp -r /x3/share/x3/plugins /x3/data/ 2>/dev/null || true
fi

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
            # Escape special characters for sed (/, &, \)
            escaped_value=$(printf '%s\n' "$value" | sed -e 's/[\/&]/\\&/g')
            sed -i "s|${placeholder}|${escaped_value}|g" "$BASECONF"
        else
            echo "Warning: No value set for ${varname}, leaving ${placeholder} unchanged"
        fi
    done

    echo "Generated $BASECONF from template"
fi

# Run the command passed to docker (CMD from Dockerfile)
exec "$@"
