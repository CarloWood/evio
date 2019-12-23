#! /bin/bash

# This script is not supposed to be run by the user.

# Use environment variable if provided.
AUTOMAKE=${AUTOMAKE:-automake}
ACLOCAL=${ACLOCAL:-`echo $AUTOMAKE | sed -e 's/automake/aclocal/'`}
AUTOCONF=${AUTOCONF:-autoconf}
AUTOHEADER=${AUTOHEADER:-`echo $AUTOCONF | sed -e 's/autoconf/autoheader/'`}
AUTOM4TE=${AUTOM4TE:-`echo $AUTOCONF | sed -e 's/autoconf/autom4te/'`}
LIBTOOL=${LIBTOOL:-libtool}
LIBTOOLIZE=${LIBTOOLIZE:-`echo $LIBTOOL | sed -e 's/libtool/libtoolize/'`}

# Environment variables need to be exported. For example, aclocal uses AUTOM4TE to run the correct autom4te.
export AUTOMAKE ACLOCAL AUTOCONF AUTOHEADER AUTOM4TE LIBTOOL LIBTOOLIZE GETTEXT GTKDOCIZE

# Needed for aclocal.
mkdir -p m4/aclocal

# Nevertheless, lets do a sanity check...
MATRIXSSL_SRCDIR="$(dirname $0)/matrixssl"
if [ "$MATRIXSSL_SRCDIR" != "$PWD" ]; then
  echo "Run this script while inside the source directory (of matrixssl)."
  exit 1
fi

echo "Running '$LIBTOOLIZE --force --automake' ..."
"$LIBTOOLIZE" --force --automake || exit 1

echo "Running '$ACLOCAL -I m4/aclocal -I ../../../cwm4/aclocal' ..."
"$ACLOCAL" -I m4/aclocal -I ../../../cwm4/aclocal || exit 1

echo "Running '$AUTOHEADER' ..."
"$AUTOHEADER" || exit 1

echo "Running '$AUTOMAKE --add-missing --foreign' ..."
"$AUTOMAKE" --add-missing --foreign || exit 1

echo "Running '$AUTOCONF' ..."
"$AUTOCONF" || exit 1
sed -i 's/rm -f core/rm -f/' configure
