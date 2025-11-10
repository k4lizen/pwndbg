#!/usr/bin/env python

import idaapi
from xmlrpc.server import SimpleXMLRPCServer, SimpleXMLRPCRequestHandler
import threading
import functools

import ida_hexrays
import ida_funcs
import idc
import idautils

from typing import Optional, Dict


class RequestHandler(SimpleXMLRPCRequestHandler):
    rpc_paths = ("/RPC2",)
#
# Wrappers for IDA Main thread r/w operations
#
#
# a special note about these functions:
# Any operation that needs to do some type of write to the ida db (idb), needs to be in the main
# thread due to some ida constraints. Sometimes reads also need to be in the main thread.
#


def is_mainthread():
    """
    Return a bool that indicates if this is the main application thread.
    """
    return isinstance(threading.current_thread(), threading._MainThread)


def execute_sync(func, sync_type):
    """
    Synchronize with the disassembler for safe database access.
    Modified from https://github.com/vrtadmin/FIRST-plugin-ida
    """

    @functools.wraps(func)
    def wrapper(*args, **kwargs) -> object:
        output = [None]

        #
        # this inline function definition is technically what will execute
        # in the context of the main thread. we use this thunk to capture
        # any output the function may want to return to the user.
        #

        def thunk():
            output[0] = func(*args, **kwargs)
            return 1

        if is_mainthread():
            thunk()
        else:
            idaapi.execute_sync(thunk, sync_type)

        # return the output of the synchronized execution
        return output[0]
    return wrapper


def execute_read(func):
    return execute_sync(func, idaapi.MFF_READ)


def execute_write(func):
    return execute_sync(func, idaapi.MFF_WRITE)


def execute_ui(func):
    return execute_sync(func, idaapi.MFF_FAST)


#
# Decompilation API
#

class DecompilerServer:
    def __init__(self) -> None:
        self._base_addr: int = idaapi.get_imagebase()

        # We don't want to recalculate from scratch every time,
        # so we will calculate once on initialization and then update
        # via IDA hooks.
        self._global_vars: dict = self._get_global_vars()
        self._function_headers: dict = self._get_function_headers()

    def rebase_from_outside(self, addr: int) -> int:
        """
        The given address from outside (from Pwndbg) is expected to be the relative
        offset from the start of the image/file.

        We will rebase it on top of what IDA is using for the "base address"
        of the image, so we can operate on it directly. The ida base address
        is zero in most cases.
        """
        assert addr > 0
        return addr + self._base_addr

    def rebase_for_outside(self, addr: int) -> int:
        """
        The given address is a valid address for IDA, i.e. it takes into account
        self._base_address.

        We will make the address be relative to the start of the image/file so it
        can be safely returned to outside.
        """
        assert addr > 0
        return addr - self._base_addr

    @execute_read
    def decompile(self, addr: int) -> Optional[dict]:
        """
        If decompilation is successfull will return a dictionary
        {
            "decompilation": decomp_lines,   # list[str]
            "curr_line": cur_line_num,       # int
            "func_name": func_name           # str
        }
        and None otherwise (cannot find function, cannot decompile,
        cannot locate line in function).

        Expects outside address.
        """
        addr = self.rebase_from_outside(addr)

        # get the function
        ida_func = ida_funcs.get_func(addr)
        if not ida_func:
            return None

        func_addr = ida_func.start_ea
        func_name: str = idc.get_func_name(func_addr)

        # attempt decompilation
        try:
            cfunc = ida_hexrays.decompile(func_addr)
        except Exception:
            return None

        # locate decompilation line
        item = cfunc.body.find_closest_addr(addr)
        y_holder = idaapi.int_pointer()
        if not cfunc.find_item_coords(item, None, y_holder):
            # if idaapi failes, try a dirty search!
            up = cfunc.body.find_closest_addr(addr - 0x10)
            if not cfunc.find_item_coords(up, None, y_holder):
                down = cfunc.body.find_closest_addr(addr + 0x10)
                if not cfunc.find_item_coords(down, None, y_holder):
                    return None

        cur_line_num: int = y_holder.value()

        # decode ida lines
        enc_lines = cfunc.get_pseudocode()

        # FIXME: do i actually want the color here maybe?
        decomp_lines: list[str] = [idaapi.tag_remove(li.line) for li in enc_lines]

        return {"decompilation": decomp_lines, "curr_line": cur_line_num, "func_name": func_name}

    @execute_read
    def function_variables(self, addr: int) -> Optional[dict]:
        """
        If successfull will return a dictionary
        {
            "stack_vars": {
                "<offset1>": {
                    "name": stack_var_name, # str
                    "type": stack_var_type  # str
                }, ...
            },
            "reg_vars": {
                "<variable_name_1>": {
                    "reg_name": register_name,  # str
                    "type": reg_var_type        # str
                }, ...
            }
        }
        and None otherwise (cannot find function, cannot decompile).

        Expects outside address.
        """
        addr = self.rebase_from_outside(addr)

      # get the function
        ida_func = ida_funcs.get_func(addr)
        if not ida_func:
            return None
        func_addr = ida_func.start_ea

        # attempt decompilation
        try:
            cfunc = ida_hexrays.decompile(func_addr)
        except Exception:
            return None

        # get var info
        stack_vars = {}
        reg_vars = {}

        for var in cfunc.lvars:
            if not var.name:
                continue

            # stack variables
            if var.is_stk_var():
                offset = cfunc.mba.stacksize - var.location.stkoff()
                stack_vars[str(offset)] = {
                    "name": var.name,
                    "type": str(var.type())
                }

            # register variables
            elif var.is_reg_var():
                regnum = var.get_reg1()
                reg_name = idaapi.get_mreg_name(regnum, var.width)

                reg_vars[var.name] = {
                    "reg_name": reg_name,
                    "type": str(var.type())
                }

        return {"stack_vars": stack_vars, "reg_vars": reg_vars}

    @execute_read
    def _get_function_headers(self) -> dict:
        """
        Fetches the function headers from IDA from scratch.

        Returns dictionary
        {
            "<func_offset1>": {
                "name": func_name,  # str
                "size": func_size,  # int
            }, ...
        }
        """
        resp = {}
        # no cache, compute it
        for f_addr in idautils.Functions():
            # assure the function is not a linked library function
            if not ((idc.get_func_flags(f_addr) & idc.FUNC_LIB) == idc.FUNC_LIB):
                func_name = ida_funcs.get_func_name(f_addr)
                if not isinstance(func_name, str):
                    continue

                # double check for .plt or .got names
                if func_name.startswith(".") or "@" in func_name:
                    continue

                func_size = ida_funcs.get_func(f_addr).size()
                resp[str(self.rebase_for_outside(f_addr))] = {
                    "name": func_name,
                    "size": func_size
                }
        return resp


    def function_headers(self) -> dict:
        """
        Returns dictionary
        {
            "<func_offset1>": {
                "name": func_name,  # str
                "size": func_size,  # int
            }, ...
        }
        """
        return self._function_headers

        # check if a cache is available
        if self._function_headers is not None:
            return self._function_headers

        resp = {}
        # no cache, compute it
        for f_addr in idautils.Functions():
            # assure the function is not a linked library function
            if not ((idc.get_func_flags(f_addr) & idc.FUNC_LIB) == idc.FUNC_LIB):
                func_name = ida_funcs.get_func_name(f_addr)
                if not isinstance(func_name, str):
                    continue

                # double check for .plt or .got names
                if func_name.startswith(".") or "@" in func_name:
                    continue

                func_size = ida_funcs.get_func(f_addr).size()
                resp[str(self.rebase_for_outside(f_addr))] = {
                    "name": func_name,
                    "size": func_size
                }

        self._function_headers = resp
        return self._function_headers

    @execute_read
    def _get_global_vars(self) -> dict:
        """
        Fetches globals from IDA from scratch.

        Returns dictionary
        {
            "<global_var_offset1>": {
                "name": name   # str
            }, ...
        }
        """
        resp = {}
        # FIXME: this is kinda bad, we could have many more
        # interesting sections
        known_segs = [".data", ".bss"]
        for seg_name in known_segs:
            seg = idaapi.get_segm_by_name(seg_name)
            if not seg:
                continue

            for seg_ea in range(seg.start_ea, seg.end_ea):
                xrefs = idautils.XrefsTo(seg_ea)
                try:
                    next(xrefs)
                except StopIteration:
                    continue

                name = idaapi.get_name(seg_ea)
                if not name:
                    continue

                resp[str(self.rebase_for_outside(seg_ea))] = {
                    "name": name
                }

        return resp

    def global_vars(self) -> dict:
        """
        Returns dictionary
        {
            "<global_var_offset1>": {
                "name": name   # str
            }, ...
        }
        """
        return self._global_vars

    @execute_read
    def structs(self):
        resp = {}
        for i in range(idaapi.get_struc_qty()):
            struct_id = idaapi.get_struc_by_idx(i)
            struct = idaapi.get_struc(struct_id)
            struct_info = {
                "name": idaapi.get_struc_name(struct.id),
                "members": []
            }

            for member in struct.members:
                member_info = {
                    "name": idaapi.get_member_name(member.id)
                }

                tif = idaapi.tinfo_t()
                if idaapi.get_member_tinfo(tif, member):
                    member_info["type"] = tif.__str__()
                member_info["size"] = tif.get_size()
                struct_info["members"].append(member_info)

            resp["struct_info"].append(struct_info)
        return resp

    #
    # XMLRPC Server
    #

    def ping(self):
        return True

    def start_xmlrpc_server(self, host: str, port: int):
        """
        Initialize the XMLRPC thread.
        """

        print("[+] Starting XMLRPC server: {}:{}".format(host, port))
        self.server = SimpleXMLRPCServer(
            (host, port),
            requestHandler=RequestHandler,
            logRequests=False,
            allow_none=True
        )
        self.server.register_introspection_functions()
        self.server.register_function(self.decompile)
        self.server.register_function(self.function_variables)
        self.server.register_function(self.function_headers)
        self.server.register_function(self.global_vars)
        self.server.register_function(self.structs)
        self.server.register_function(self.ping)
        print("[+] Registered decompilation server!")
        self.server.serve_forever()

    def disconnect(self):
        self.server.shutdown()
        self.server.server_close()
