#!/usr/bin/env bash

source "$(dirname "$0")/../common.sh"

cd $PWNDBG_ABS_PATH

# Extract from sources all the information necessary to build
# the documentation. Do this from each debugger.

export PWNDBG_DOCGEN_DBGNAME="gdb"
$UV_RUN_DOCS gdb --batch -nx -ix ./gdbinit.py \
    -iex "set exception-verbose on" \
    -ix ./scripts/_docs/extract_command_docs.py \
    -ix ./scripts/_docs/extract_configuration_docs.py \
    -ix ./scripts/_docs/extract_function_docs.py \
    -nx || exit 1

# Only run the LLDB portion if it is installed (and the version is supported).
if ! command -v lldb &> /dev/null; then
    echo ""
    echo "Could not reliably extract information from sources because LLDB"
    echo "is not installed. If you did something that differs between GDB"
    echo "and LLDB you may fail the doc verification CI."
    echo "If you want to install a supported version of LLDB, see installation instructions:"
    echo "https://pwndbg.re/pwndbg/dev/contributing/setup-pwndbg-dev/#running-with-lldb"
    read -rp "Press Enter to continue or Ctrl-C to cancel..."
    # exit 0 still indicated success.
    exit 0
else
    version=$(lldb --version | awk '{print $3}')
    major_version=${version%%.*}

    if [ "$major_version" -lt 19 ]; then
        echo ""
        echo "Could not reliably extract information from sources because the"
        echo "installed version of LLDB (${version}) is too old. Only LLDB >= 19"
        echo "is supported. If you did something that differs between GDB"
        echo "and LLDB you may fail the doc verification CI."
        echo "If you want to install a supported version of LLDB, see installation instructions:"
        echo "https://pwndbg.re/pwndbg/dev/contributing/setup-pwndbg-dev/#running-with-lldb"
        read -rp "Press Enter to continue or Ctrl-C to cancel..."
        exit 0
    fi
fi

export PWNDBG_DOCGEN_DBGNAME="lldb"
{
    $UV_RUN_DOCS python pwndbg-lldb.py << EOF
set show-tips off
command script import ./scripts/_docs/extract_command_docs.py
command script import ./scripts/_docs/extract_configuration_docs.py
command script import ./scripts/_docs/extract_function_docs.py
EOF
} || exit 2
