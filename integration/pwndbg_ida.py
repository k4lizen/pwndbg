#!/usr/bin/env python

import idaapi
import ida_idaapi
import threading
import traceback
from pwndbg_ida_integration.server import DecompilerServer

# To get these^^ imports resolved, you need to tell your python LSP to
# look into the /<path to ida pro>/python/ folder.

# Useful resources:
# https://docs.hex-rays.com/developer-guide/idapython/how-to-create-a-plugin
# https://python.docs.hex-rays.com/
# https://ida-domain.docs.hex-rays.com/
# https://github.com/mahaloz/decomp2dbg/blob/main/decompilers/d2d_ida/d2d_ida/plugin.py

IDA_VERSION = idaapi.get_kernel_version()

def PLUGIN_ENTRY(*args, **kwargs):
    """Plugin entry point."""
    return IntegrationPlugin(*args, **kwargs)


class IntegrationPlugin(ida_idaapi.plugin_t):
    """Plugin actual entry point."""

    flags = idaapi.PLUGIN_FIX
    comment = "Sync IDA decompilation to Pwndbg"
    help = "Sync IDA decompilation to Pwndbg"
    wanted_name = "Pwndbg"
    wanted_hotkey = ""

    def init(self) -> ida_idaapi.plugmod_t:
        print("Initializing Pwndbg integration.")
        return IntegrationPlugmod()


class IntegrationPlugmod(ida_idaapi.plugmod_t):
    """Plugin actual actual entry point."""

    server: DecompilerServer
    host: str
    port: int

    def term(self) -> None:
        print("Disconnecting from Pwndbg integration..")
        self.server.disconnect()

    def run(self, arg) -> None:
        _ = arg
        print("Running Pwndbg integration...")
        self.server = DecompilerServer()

        self.host = "localhost"
        self.port = 43718

        t = threading.Thread(
            target=self.server.start_xmlrpc_server, kwargs={"host": self.host, "port": self.port}
        )
        t.daemon = True
        try:
            t.start()
            # start hooks on good connection
            # self.change_hook.hook()
        except Exception as e:
            print("Could not start XML RPC server for Pwndbg integration: ", e)
            traceback.print_exc()
            return
