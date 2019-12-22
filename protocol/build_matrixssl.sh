#! /bin/bash

# This script is not supposed to be run by the user.

# Nevertheless, lets do a sanity check...
if [ -e CMakeLists.txt -o -e configure.ac ]; then
  echo "Run this script while inside the build directory (of matrixssl)."
  exit 1
fi

MATRIXSSL_SRCDIR="$(dirname $0)/matrixssl"

# Try to find the architecture (this is needed when the compiler is set to clang).
CCARCH="$(gcc -print-multiarch)"
export CCARCH

# Because cmake doesn't support the GNU make jobserver when running
# a script from a COMMAND, we'll just unset MAKEFLAGS...
unset MAKEFLAGS

# If MAKEFLAGS is set, it was probably set by make as a result of
# using a Makefiles generator by cmake. In that case we are a submake
# and should use the provided jobserver instead of specifying -j.
make_command="$1"
shift
if [[ x"$MAKEFLAGS" == *"--jobserver-fds"* ]]; then
  arguments=()
  saw_j=0
  for i in "$@"
  do
    case "$i" in
      -j)
        saw_j=1
        ;;
      -j[0-9]*)
        saw_j=0
        ;;
      *)
        if [ $saw_j -eq 0 -o -z "${i##*[!0-9]*}" ]; then
          arguments+=("$i")
        fi
        saw_j=0
        ;;
    esac
  done
else
  arguments=("$@")
fi

# Print arguments, quoting them if they contain spaces.
quoted_arguments=()
declare -i len=${#arguments[@]}
for ((n = 0; n < len; n++))
do
  if [[ ${arguments[$n]} =~ [[:space:]] ]]; then
    quoted_arguments+=("\"${arguments[$n]}\"")
  else
    quoted_arguments+=("${arguments[$n]}")
  fi
done
echo "Running '$make_command ${quoted_arguments[@]}' ..."
"$make_command" "${arguments[@]}"

echo "Running '$make_command list-build-files' ..."
"$make_command" list-build-files 2>/dev/null | /bin/egrep '^(apps|crypto|core|matrixssl)/' > "$MATRIXSSL_SRCDIR/../matrixssl-build-files.new" && \
  mv "$MATRIXSSL_SRCDIR/../matrixssl-build-files.new" "$MATRIXSSL_SRCDIR/../matrixssl-build-files"
