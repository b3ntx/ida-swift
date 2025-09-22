import ida_kernwin
import ida_funcs
import ida_typeinf
import ida_nalt
import ida_hexrays
import idaapi
import idc

gRegisterToName = {
    "x20" : "self",
    "x21" : "error",
    "x22" : "context"
}

class SwiftRegisterArgsPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = "Add X20/X21/X22 registers to function signatures for Swift methods"
    help = "Right-click in a function to add Swift register arguments"
    wanted_name = "Swift Register Arguments"
    wanted_hotkey = ""

    def init(self):
        self.hooks = None
        if ida_hexrays.init_hexrays_plugin():
            self.hooks = UIHooks()
            self.hooks.hook()
            ida_kernwin.msg("Swift Register Arguments plugin initialized\n")
            return idaapi.PLUGIN_KEEP
        return idaapi.PLUGIN_SKIP

    def run(self, arg):
        ida_kernwin.msg("Swift Register Arguments running!\n")

    def term(self):
        if self.hooks:
            self.hooks.unhook()

class UIHooks(ida_kernwin.UI_Hooks):
    def finish_populating_widget_popup(self, widget, popup):
        if ida_kernwin.get_widget_type(widget) == ida_kernwin.BWN_DISASM or \
           ida_kernwin.get_widget_type(widget) == ida_kernwin.BWN_PSEUDOCODE:
            
            func = ida_funcs.get_func(idc.get_screen_ea())
            if func:
                ida_kernwin.attach_action_to_popup(widget, popup, "swift:add_x20", None)
                ida_kernwin.attach_action_to_popup(widget, popup, "swift:add_x21", None)
                ida_kernwin.attach_action_to_popup(widget, popup, "swift:add_x22", None)

    def hook(self):
        ida_kernwin.register_action(ida_kernwin.action_desc_t(
            "swift:add_x20",
            "Add register X20 to function signature",
            AddRegisterHandler("X20"),
            None,
            "Add X20 (self/this) to function signature",
            -1
        ))
        
        ida_kernwin.register_action(ida_kernwin.action_desc_t(
            "swift:add_x21",
            "Add register X21 to function signature",
            AddRegisterHandler("X21"),
            None,
            "Add X21 (error) to function signature",
            -1
        ))
        
        ida_kernwin.register_action(ida_kernwin.action_desc_t(
            "swift:add_x22",
            "Add register X22 to function signature",
            AddRegisterHandler("X22"),
            None,
            "Add X22 (task) to function signature",
            -1
        ))
        
        super().hook()

    def unhook(self):
        ida_kernwin.unregister_action("swift:add_x20")
        ida_kernwin.unregister_action("swift:add_x21")
        ida_kernwin.unregister_action("swift:add_x22")
        super().unhook()

class AddRegisterHandler(ida_kernwin.action_handler_t):
    def __init__(self, register):
        ida_kernwin.action_handler_t.__init__(self)
        self.register = register

    def activate(self, ctx):
        ea = idc.get_screen_ea()
        func = ida_funcs.get_func(ea)
        
        if not func:
            ida_kernwin.msg("No function at current address\n")
            return 1
        
        add_register_to_signature(func.start_ea, self.register)
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_FOR_WIDGET

def get_register_type(register):
    """
    Get the appropriate type for a register.
    For X22, use swift::AsyncContext* if it exists, otherwise void*.
    For other registers, use void*.
    """
    # For X22, try to use swift::AsyncContext* if the type exists
    if register.upper() == "X22":
        til = idaapi.get_idati()
        async_context_type = ida_typeinf.tinfo_t()
        
        # Check if swift::AsyncContext type exists
        if async_context_type.get_named_type(til, "swift::AsyncContext"):
            # Create pointer to swift::AsyncContext
            ptr_type = ida_typeinf.tinfo_t()
            ptr_type.create_ptr(async_context_type)
            ida_kernwin.msg(f"Using swift::AsyncContext* for X22\n")
            return ptr_type
        else:
            ida_kernwin.msg(f"swift::AsyncContext type not found, using void* for X22\n")
    
    # Default to void* for all other cases
    void_ptr = ida_typeinf.tinfo_t()
    void_ptr.create_ptr(ida_typeinf.tinfo_t(ida_typeinf.BTF_VOID))
    return void_ptr

def add_register_to_signature(func_ea, register):
    tinfo = ida_typeinf.tinfo_t()
    if not ida_nalt.get_tinfo(tinfo, func_ea):
        func_details = ida_typeinf.func_type_data_t()
        # thanks for changing the API, hexrays!
        if hasattr(func_details, 'cc'):
            func_details.cc = ida_typeinf.CM_CC_SPECIAL
        else:
            func_details.set_cc(ida_typeinf.CM_CC_SPECIAL)
        
        ret_type = ida_typeinf.tinfo_t()
        ret_type.create_simple_type(ida_typeinf.BTF_VOID)
        func_details.rettype = ret_type
        
        tinfo.create_func(func_details)
        ida_kernwin.msg(f"Created new __usercall signature for function at 0x{func_ea:X}\n")
    
    func_details = ida_typeinf.func_type_data_t()
    if not tinfo.get_func_details(func_details):
        ida_kernwin.msg("Failed to get function details\n")
        return False
    
    # thanks for changing the API, hexrays!
    cc = func_details.cc if hasattr(func_details, 'cc') else func_details.get_explicit_cc()

    if cc != ida_typeinf.CM_CC_SPECIAL and cc != ida_typeinf.CM_CC_SPECIALE and cc != ida_typeinf.CM_CC_SPECIALP:
        # thanks for changing the API, hexrays!
        if hasattr(func_details, 'cc'):
            func_details.cc = ida_typeinf.CM_CC_SPECIAL
        else:
            func_details.set_cc(ida_typeinf.CM_CC_SPECIAL)
        ida_kernwin.msg(f"Converting function to __usercall\n")
    
    for arg in func_details:
        if arg.argloc.is_reg1() and arg.argloc.reg1() == get_register_number(register):
            ida_kernwin.msg(f"Register {register} already in signature\n")
            return False
    
    assert( register.lower() in gRegisterToName )
    
    new_arg = ida_typeinf.funcarg_t()
    new_arg.type = get_register_type(register)
    new_arg.name = gRegisterToName[register.lower()]
    new_arg.argloc = ida_typeinf.argloc_t()
    
    reg_num = get_register_number(register)
    if reg_num == -1:
        ida_kernwin.msg(f"Unknown register: {register}\n")
        return False
    
    new_arg.argloc.set_reg1(reg_num)
    new_arg.flags = ida_typeinf.FAI_HIDDEN
    
    # Rebuild the argument list with Swift ABI registers first
    # Define the order for Swift ABI registers
    swift_reg_order = {"X20": 0, "X21": 1, "X22": 2}
    
    # Store existing arguments by iterating with index
    existing_args = []
    for i in range(func_details.size()):
        arg = func_details[i]
        # Create a copy of the argloc to avoid reference issues
        argloc_copy = ida_typeinf.argloc_t(arg.argloc)
        
        # Store a copy of the argument data
        arg_copy = {
            'name': arg.name,
            'type': arg.type.copy(),
            'argloc': argloc_copy,
            'cmt': arg.cmt,
            'flags': arg.flags
        }
        existing_args.append(arg_copy)
    
    # Separate existing args into Swift ABI args and regular args
    swift_args = []
    regular_args = []
    
    for arg_data in existing_args:
        if arg_data['argloc'].is_reg1():
            reg_name = get_register_name(arg_data['argloc'].reg1())
            if reg_name and reg_name.upper() in swift_reg_order:
                swift_args.append((swift_reg_order[reg_name.upper()], arg_data))
            else:
                regular_args.append(arg_data)
        else:
            regular_args.append(arg_data)
    
    # Add the new Swift register data with a proper argloc copy
    new_argloc = ida_typeinf.argloc_t()
    new_argloc.set_reg1(reg_num)
    
    new_arg_data = {
        'name': gRegisterToName[register.lower()],
        'type': get_register_type(register),
        'argloc': new_argloc,
        'cmt': "",
        'flags': ida_typeinf.FAI_HIDDEN
    }
    swift_args.append((swift_reg_order[register.upper()], new_arg_data))
    
    # Sort Swift args by their defined order
    swift_args.sort(key=lambda x: x[0])
    
    # Clear the function arguments using the proper method
    while func_details.size() > 0:
        func_details.pop_back()
    
    # Add Swift ABI registers first
    for _, arg_data in swift_args:
        fa = ida_typeinf.funcarg_t()
        fa.name = arg_data['name']
        fa.type = arg_data['type']
        fa.argloc = arg_data['argloc']
        fa.cmt = arg_data['cmt']
        fa.flags = arg_data['flags']
        func_details.push_back(fa)
    
    # Add regular arguments after
    for arg_data in regular_args:
        fa = ida_typeinf.funcarg_t()
        fa.name = arg_data['name']
        fa.type = arg_data['type']
        fa.argloc = arg_data['argloc']
        fa.cmt = arg_data['cmt']
        fa.flags = arg_data['flags']
        func_details.push_back(fa)
    
    new_tinfo = ida_typeinf.tinfo_t()
    if not new_tinfo.create_func(func_details):
        ida_kernwin.msg("Failed to create new function type\n")
        return False
    
    if ida_typeinf.apply_tinfo(func_ea, new_tinfo, ida_typeinf.TINFO_DEFINITE):
        ida_kernwin.msg(f"Successfully added {register} to function signature at 0x{func_ea:X}\n")
        ida_hexrays.mark_cfunc_dirty(func_ea)
        return True
    else:
        ida_kernwin.msg(f"Failed to apply new signature to function at 0x{func_ea:X}\n")
        return False

def get_register_number(reg_name):
    # ARM64 register IDs in IDA
    reg_map = {
        "X20": 149,  # 129 + 20
        "X21": 150,  # 129 + 21
        "X22": 151   # 129 + 22
    }
    return reg_map.get(reg_name, -1)

def get_register_name(reg_num):
    # Reverse mapping of ARM64 register IDs to names
    reg_map = {
        149: "X20",
        150: "X21",
        151: "X22"
    }
    return reg_map.get(reg_num, None)

def PLUGIN_ENTRY():
    return SwiftRegisterArgsPlugin()