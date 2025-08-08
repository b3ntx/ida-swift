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
    "x22" : "task"
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
        pass

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

def add_register_to_signature(func_ea, register):
    tinfo = ida_typeinf.tinfo_t()
    if not ida_nalt.get_tinfo(tinfo, func_ea):
        func_details = ida_typeinf.func_type_data_t()
        func_details.cc = ida_typeinf.CM_CC_SPECIAL
        
        ret_type = ida_typeinf.tinfo_t()
        ret_type.create_simple_type(ida_typeinf.BTF_VOID)
        func_details.rettype = ret_type
        
        tinfo.create_func(func_details)
        ida_kernwin.msg(f"Created new __usercall signature for function at 0x{func_ea:X}\n")
    
    func_details = ida_typeinf.func_type_data_t()
    if not tinfo.get_func_details(func_details):
        ida_kernwin.msg("Failed to get function details\n")
        return False
    
    if func_details.cc != ida_typeinf.CM_CC_SPECIAL and func_details.cc != ida_typeinf.CM_CC_SPECIALE and func_details.cc != ida_typeinf.CM_CC_SPECIALP:
        func_details.cc = ida_typeinf.CM_CC_SPECIAL
        ida_kernwin.msg(f"Converting function to __usercall\n")
    
    for arg in func_details:
        if arg.argloc.is_reg1() and arg.argloc.reg1() == get_register_number(register):
            ida_kernwin.msg(f"Register {register} already in signature\n")
            return False
    
    assert( register.lower() in gRegisterToName )
    
    new_arg = ida_typeinf.funcarg_t()
    new_arg.type = ida_typeinf.tinfo_t()
    new_arg.type.create_ptr(ida_typeinf.tinfo_t(ida_typeinf.BTF_VOID))
    new_arg.name = gRegisterToName[register.lower()]
    new_arg.argloc = ida_typeinf.argloc_t()
    
    reg_num = get_register_number(register)
    if reg_num == -1:
        ida_kernwin.msg(f"Unknown register: {register}\n")
        return False
    
    new_arg.argloc.set_reg1(reg_num)
    new_arg.flags = ida_typeinf.FAI_HIDDEN
    
    func_details.push_back(new_arg)
    
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

def PLUGIN_ENTRY():
    return SwiftRegisterArgsPlugin()