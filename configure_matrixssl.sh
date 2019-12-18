#! /bin/bash

MATRIXSSL_SRCDIR="$1/matrixssl"
MATRIXSSL_BUILDDIR="$PWD"

cd "$MATRIXSSL_SRCDIR" || exit 1
echo "Running 'libtoolize --force --automake'..."
libtoolize --force --automake || exit 1
echo "Running 'aclocal -I m4/aclocal -I \"$1\"/../cwm4/aclocal'..."
aclocal -I m4/aclocal -I "$1"/../cwm4/aclocal || exit 1
echo "Running 'autoheader'..."
autoheader || exit 1
echo "Running 'automake --add-missing --foreign'..."
automake --add-missing --foreign || exit 1
echo "Running 'autoconf'..."
autoconf || exit 1

cd "$MATRIXSSL_BUILDDIR" || exit 1
echo "Running '\"$MATRIXSSL_SRCDIR\"/configure'..."
"$MATRIXSSL_SRCDIR"/configure --enable-maintainer-mode || exit 1
