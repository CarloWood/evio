#! /bin/bash

# This script is not supposed to be run by the user.

# Nevertheless, lets do a sanity check...
if [ -e CMakeLists.txt -o -e configure.ac ]; then
  echo "Run this script while inside the build directory (of matrixssl)."
  exit 1
fi

MATRIXSSL_SRCDIR="$(dirname $0)/matrixssl"

echo "Running $@ ..."
"$@"
echo "Running $@ list-build-files ..."
"$@" list-build-files 2>/dev/null | /bin/egrep '^(apps|crypto|core|matrixssl)/' > "$MATRIXSSL_SRCDIR/../matrixssl-build-files.new" && \
  mv "$MATRIXSSL_SRCDIR/../matrixssl-build-files.new" "$MATRIXSSL_SRCDIR/../matrixssl-build-files"
