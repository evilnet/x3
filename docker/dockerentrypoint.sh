#!/bin/bash

# Apply ENV to ircd.conf
# ...

BASECONFDIST=/x3/x3.conf-dist
BASECONF=/x3/x3.conf

if [ -z "${X3_GENERAL_NAME}" ]; then
        X3_GENERAL_NAME="x3.network"
fi
if [ -z "${X3_GENERAL_BIND_ADDRESS}" ]; then
        X3_GENERAL_BIND_ADDRESS="127.0.0.1"
fi
if [ -z "${X3_GENERAL_DESCRIPTION}" ]; then
        X3_GENERAL_DESCRIPTION="Network Services"
fi
if [ -z "${X3_GENERAL_DOMAIN}" ]; then
        X3_GENERAL_DOMAIN="example.com"
fi
if [ -z "${X3_GENERAL_NUMERIC}" ]; then
        X3_GENERAL_NUMERIC="199"
fi
if [ -z "${X3_GENERAL_DESCRIPTION}" ]; then
        X3_GENERAL_CONNECT_PORT="8888"
fi
if [ -z "${X3_GENERAL_CONNECT_PASSWORD}" ]; then
        X3_GENERAL_CONNECT_PASSWORD="abcdefg"
fi
if [ -z "${X3_ADMIN_CONTACT}" ]; then
        X3_GENERAL_BIND_ADDRESS="127.0.0.1"
fi
if [ -z "${X3_UPLINK_ADDRESS}" ]; then
        X3_GENERAL_ADDRESS="172.0.0.1"
fi
if [ -z "${X3_UPLINK_PORT}" ]; then
        X3_UPLINK_PORT="8888"
fi
if [ -z "${X3_UPLINK_PASSWORD}" ]; then
        X3_UPLINK_PASSWORD=100
fi


#Copy the template to base.conf location
cp $BASECONFDIST $BASECONF

#Modify base.conf template with env variables
sed -i "s/%X3_GENERAL_NAME%/${X3_GENERAL_NAME}/g" $BASECONF
sed -i "s/%X3_GENERAL_GENERAL_BIND_ADDRESS%/${X3_GENERAL_GENERAL_BIND_ADDRESS}/g" $BASECONF
sed -i "s/%X3_GENERAL_DESCRIPTION%/${X3_GENERAL_DESCRIPTION}/g" $BASECONF
sed -i "s/%X3_GENERAL_DOMAIN%/${X3_GENERAL_DOMAIN}/g" $BASECONF
sed -i "s/%X3_GENERAL_NUMERIC%/${X3_GENERAL_NUMERIC}/g" $BASECONF
sed -i "s/%X3_GENERAL_GENERAL_CONNECT_PORT%/${X3_GENERAL_GENERAL_CONNECT_PORT}/g" $BASECONF
sed -i "s/%X3_GENERAL_CONNECT_PASSWORD%/${X3_GENERAL_CONNECT_PASSWORD}/g" $BASECONF
sed -i "s/%X3_GENERAL_BIND_ADDRESS%/${X3_GENERAL_BIND_ADDRESS}/g" $BASECONF
sed -i "s/%X3_GENERAL_ADDRESS%/${X3_GENERAL_ADDRESS}/g" $BASECONF
sed -i "s/%X3_UPLINK_PORT%/${X3_UPLINK_PORT}/g" $BASECONF
sed -i "s/%X3_UPLINK_PASSWORD%/${X3_UPLINK_PASSWORD}/g" $BASECONF
#sed -i "s/%X3_XX%/${X3_XX}/g" $BASECONF

#If cmd is the ircd...
#if [ "$1" == "/x3/x3" ]; then
    # Generate a pem file if there isnt one...
    #if [ ! -f /m ]; then
        #openssl x509 -subject -dates -fingerprint -noout -in $IRCDPEM
    #fi
#fi

#Now run CMD from Dockerfile...

exec "$@"


