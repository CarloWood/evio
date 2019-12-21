#! /bin/bash

# This script is not supposed to be run by the user.

# Nevertheless, lets do a sanity check...
if [ -e CMakeLists.txt -o -e configure.ac ]; then
  echo "Run this script while inside the build directory (of matrixssl)."
  exit 1
fi

MATRIXSSL_SRCDIR="$(dirname $0)/matrixssl"

echo "Running '\"$MATRIXSSL_SRCDIR\"/configure --enable-maintainer-mode' ..."
"$MATRIXSSL_SRCDIR"/configure --enable-maintainer-mode || exit 1
echo "Running $@ list-configure-files ..."
"$@" list-configure-files 2>/dev/null | /bin/grep -v ' ' > "$MATRIXSSL_SRCDIR/../matrixssl-configure-files.new" && \
  mv "$MATRIXSSL_SRCDIR/../matrixssl-configure-files.new" "$MATRIXSSL_SRCDIR/../matrixssl-configure-files"
