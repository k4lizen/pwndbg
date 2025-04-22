#!/bin/sh

# Tell the script to verify instead of generate files.
export PWNDBG_GEN_DOC_JUST_VERIFY=1
# Run the verifier inside gdb so everything resolves correctly.
# uv run --group docs gdb -nx \
#     --ex "source ./gdbinit.py" \
#     --ex "set exception-verbose on" \
#     --ex "maintenance set internal-error corefile yes" \
#     --ex "source ./scripts/_gen_function_docs.py" \


uv run --group docs ~/opt/binutils-gdb-build/gdb/gdb --data-dir=/home/$USER/opt/binutils-gdb-build/gdb/data-directory/ -nx \
    --ex "source ./gdbinit.py" \
    --ex "maintenance set internal-error corefile yes" \
    --ex "source ./thing.py"
