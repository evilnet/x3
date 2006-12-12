#!/bin/sh
# 
# This installs libtre in $HOME, 

TRE_VERSION=0.7.5
MAKE="make"

OLD_DIR=`pwd`
SELF_DIR=`dirname $0`

cd $SELF_DIR
cp tre.tar.gz tre.tar.gz.bak
gunzip -f tre.tar.gz
cp tre.tar.gz.bak tre.tar.gz
tar xf tre.tar

cd $OLD_DIR/$SELF_DIR/tre-$TRE_VERSION
./configure --disable-agrep --disable-shared --disable-system-abi --disable-wchar --disable-multibyte --prefix=$HOME
$MAKE || exit 1
$MAKE install || exit 1
cd $OLD_DIR

echo ""
echo "LibTRE is now installed in $HOME/include and $HOME/lib. You may now configure X3."

