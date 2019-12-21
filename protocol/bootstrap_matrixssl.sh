#! /bin/bash

# This script is not supposed to be run by the user.

# Nevertheless, lets do a sanity check...
MATRIXSSL_SRCDIR="$(dirname $0)/matrixssl"
if [ "$MATRIXSSL_SRCDIR" != "$PWD" ]; then
  echo "Run this script while inside the source directory (of matrixssl)."
  exit 1
fi

echo "Running 'libtoolize --force --automake' ..."
libtoolize --force --automake || exit 1

echo "Running 'aclocal -I m4/aclocal -I ../../../cwm4/aclocal' ..."
aclocal -I m4/aclocal -I ../../../cwm4/aclocal || exit 1

echo "Running 'autoheader' ..."
autoheader || exit 1

echo "Running 'automake --add-missing --foreign' ..."
automake --add-missing --foreign || exit 1

echo "Running 'autoconf' ..."
autoconf || exit 1
sed -i 's/rm -f core/rm -f/' configure
