#!/bin/sh
# 
# This installs coredumper in $HOME, 

CORE_VERSION=1.1
MAKE="make"

OLD_DIR=`pwd`
SELF_DIR=`dirname $0`

cd $SELF_DIR
cp coredumper.tar.gz coredumper.tar.gz.bak
gunzip -f coredumper.tar.gz
cp coredumper.tar.gz.bak coredumper.tar.gz
tar xf coredumper.tar

cd $OLD_DIR/$SELF_DIR/coredumper-$CORE_VERSION
./configure --prefix=$HOME
$MAKE || exit 1
$MAKE install || exit 1
cd $OLD_DIR

echo ""
echo "Core Dumper LIBS are now installed in $HOME/include and $HOME/lib. You may now configure X3."

