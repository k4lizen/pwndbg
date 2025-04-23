#!/bin/sh

# Tell the script to verify instead of generate files.
export PWNDBG_GEN_DOC_JUST_VERIFY=1
# Run the verifier inside gdb so everything resolves correctly.
# uv run --group docs gdb -nx \
#     --ex "source ./gdbinit.py" \
#     --ex "set exception-verbose on" \
#     --ex "maintenance set internal-error corefile yes" \
#     --ex "source ./thing.py"
#     # --ex "source ./scripts/_gen_function_docs.py" \



# uv run --group docs ~/opt/gdb-build-15.1/gdb/gdb \
#     --data-dir=/home/$USER/opt/gdb-build-15.1/gdb/data-directory/ -nx \
#     --ex "source ./gdbinit.py" \
#     --ex "set exception-verbose on" \
#     --ex "maintenance set internal-error corefile yes" \
#     # --ex "source ./thing.py"

# uv run --group docs ~/opt/gdb-build-master/gdb/gdb \
#     --data-dir=/home/$USER/opt/gdb-build-master/gdb/data-directory/ -nx \
#     --ex "source ./gdbinit.py" \
#     --ex "set exception-verbose on" \
#     --ex "maintenance set internal-error corefile yes" \
#     # --ex "source ./thing.py"

# for bisect
uv run --group docs ~/opt/gdb-build-bisect/gdb/gdb \
    --data-dir=/home/$USER/opt/gdb-build-bisect/gdb/data-directory/ -nx \
    --ex "source ./gdbinit.py" \
    --ex "set exception-verbose on" \
    --ex "maintenance set internal-error corefile yes" \
    --ex "source ./thing.py"
