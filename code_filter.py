import ida_kernwin
import ida_netnode
import ida_idaapi
import ida_funcs
import ida_name
import ida_nalt
import ida_gdl
import ida_dbg
import ida_idd
import pickle
import copy

class CodeFilterChooser(ida_kernwin.Choose):

    def __init__(self):
        super().__init__(
            "Code Filter",
            [["Name", 20], ["Address", 20], ["Executed", 10], ["Execution Index", 10], ["Execution Count", 10], ["Comment", 30]],
            flags = ida_kernwin.CH_MULTI | ida_kernwin.CH_KEEP
        )
        self.execution_count_enabled = False
        self.entries = []

    def OnGetSize(self):
        return len(self.entries)

    def OnGetLine(self, n):
        return self.entries[n]

    def OnSelectLine(self, n):
        ida_kernwin.jumpto(int(self.entries[n[0]][1], 16))

    def OnPopup(self, widget, popup_handle):
        ida_kernwin.attach_action_to_popup(widget, popup_handle,"chooser_start_function_search",None, ida_kernwin.SETMENU_APP)
        ida_kernwin.attach_action_to_popup(widget, popup_handle,"chooser_start_block_search",None, ida_kernwin.SETMENU_APP)
        ida_kernwin.attach_action_to_popup(widget, popup_handle,"chooser_remove_all_entries",None, ida_kernwin.SETMENU_ENSURE_SEP)
        ida_kernwin.attach_action_to_popup(widget, popup_handle,"chooser_remove_selected_entries",None, ida_kernwin.SETMENU_APP)
        ida_kernwin.attach_action_to_popup(widget, popup_handle,"chooser_remove_executed_entries",None, ida_kernwin.SETMENU_APP)
        ida_kernwin.attach_action_to_popup(widget, popup_handle,"chooser_remove_unexecuted_entries",None, ida_kernwin.SETMENU_APP)
        ida_kernwin.attach_action_to_popup(widget, popup_handle, "chooser_load_state", None, ida_kernwin.SETMENU_ENSURE_SEP)
        ida_kernwin.attach_action_to_popup(widget, popup_handle, "chooser_save_state", None, ida_kernwin.SETMENU_APP)
        ida_kernwin.attach_action_to_popup(widget, popup_handle, "chooser_save_state_as", None, ida_kernwin.SETMENU_APP)
        ida_kernwin.attach_action_to_popup(widget, popup_handle, "chooser_delete_state", None, ida_kernwin.SETMENU_APP)

        ida_kernwin.attach_action_to_popup(widget, popup_handle, "chooser_clear_execution_count", None, ida_kernwin.SETMENU_ENSURE_SEP)
        if self.execution_count_enabled:
            ida_kernwin.attach_action_to_popup(widget, popup_handle, "chooser_disable_execution_count", None, ida_kernwin.SETMENU_APP)
        else:
            ida_kernwin.attach_action_to_popup(widget, popup_handle, "chooser_enable_execution_count", None, ida_kernwin.SETMENU_APP)

        ida_kernwin.attach_action_to_popup(widget, popup_handle, "chooser_set_comment", None, ida_kernwin.SETMENU_APP)

    def Update(self, entries):
        self.entries = entries
        self.Refresh()

    def SetExecutionCount(self, status):
        self.execution_count_enabled = status

class DropdownFormLoad(ida_kernwin.Form):

    def __init__(self, options):
        form_layout = "STARTITEM 0\n" \
                      "BUTTON YES* Load\n" \
                      "BUTTON CANCEL Cancel\n" \
                      "Load State\n" \
                      "<State :{cbDropdown}>"
        ida_kernwin.Form.__init__(self, form_layout, {'cbDropdown': ida_kernwin.Form.DropdownListControl(items=options)})

class CodeFilter(ida_idaapi.plugin_t):

    flags = ida_idaapi.PLUGIN_MOD
    comment = "This plugin implements functionality similar to cheat engine's code filter"
    help = "Plugin that uses breakpoints to find executed and non executed functions or blocks"
    wanted_name = "Code Filter"
    wanted_hotkey = "Ctrl-Shift-C"

    def init(self):
        self.execution_count_enabled = False

        self.cf_chooser = CodeFilterChooser()

        self.cf_bp_hooks = DebugHooks()
        self.cf_bp_hooks.set_parent(self)

        self.cf_ui_hooks = UIHooks()
        self.cf_ui_hooks.set_parent(self)
        self.cf_ui_hooks.hook()

        self.execution_index = 0
        self.image_base = ida_nalt.get_imagebase()
        self.state_name = ""
        self.entries = []
        self.states = {}

        self.netnode = ida_netnode.netnode("CodeFilterNode", 0, True)
        netnode_blob = self.netnode.getblob(0, "B")
        if netnode_blob:
            self.states = pickle.loads(netnode_blob)

        ida_kernwin.register_action(ida_kernwin.action_desc_t("chooser_start_function_search","Start Function Search", ChooserStartFunctionSearch(self)))
        ida_kernwin.register_action(ida_kernwin.action_desc_t("chooser_start_block_search","Start Block Search From Selected", ChooserStartBlockSearch(self)))
        ida_kernwin.register_action(ida_kernwin.action_desc_t("chooser_remove_all_entries","Remove All Entries", ChooserRemoveAllEntries(self)))
        ida_kernwin.register_action(ida_kernwin.action_desc_t("chooser_remove_selected_entries","Remove Selected Entries", ChooserRemoveSelectedEntries(self)))
        ida_kernwin.register_action(ida_kernwin.action_desc_t("chooser_remove_executed_entries","Remove Executed Entries", ChooserRemoveExecutedEntries(self)))
        ida_kernwin.register_action(ida_kernwin.action_desc_t("chooser_remove_unexecuted_entries","Remove Unexecuted Entries", ChooserRemoveUnexecutedEntries(self)))
        ida_kernwin.register_action(ida_kernwin.action_desc_t("chooser_load_state","Load State", ChooserLoadState(self)))
        ida_kernwin.register_action(ida_kernwin.action_desc_t("chooser_save_state","Save State", ChooserSaveState(self)))
        ida_kernwin.register_action(ida_kernwin.action_desc_t("chooser_save_state_as","Save State as", ChooserSaveStateAs(self)))
        ida_kernwin.register_action(ida_kernwin.action_desc_t("chooser_delete_state", "Delete State", ChooserDeleteState(self)))
        ida_kernwin.register_action(ida_kernwin.action_desc_t("chooser_clear_execution_count", "Clear Execution Count", ChooserClearExecutionCount(self)))
        ida_kernwin.register_action(ida_kernwin.action_desc_t("chooser_enable_execution_count", "Enable Execution Count", ChooserEnableExecutionCount(self)))
        ida_kernwin.register_action(ida_kernwin.action_desc_t("chooser_disable_execution_count", "Disable Execution Count", ChooserDisableExecutionCount(self)))
        ida_kernwin.register_action(ida_kernwin.action_desc_t("chooser_set_comment", "Set Comment", ChooserSetComment(self)))
        ida_kernwin.register_action(ida_kernwin.action_desc_t("function_window_add_function", "Add To Code Filter", FunctionWindowAddToCodeFilter(self)))

        print("[Code Filter] Plugin initialized")
        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg):
        self.cf_bp_hooks.hook()
        self.cf_chooser.Show()
        print("[Code Filter] Plugin executed")
        return ida_idaapi.PLUGIN_OK

    def term(self):
        print("[Code Filter] Plugin terminated")

    def update(self, entries):
        self.entries = entries
        self.cf_chooser.Update(self.entries)

    def next_execution_index(self):
        self.execution_index += 1
        return self.execution_index

    def process_relocations(self):
        new_base = ida_nalt.get_imagebase()
        if new_base != self.image_base:
            print(f"[Code Filter] Image base changed from {self.image_base:#x} to {new_base:#x}, updating {len(self.entries)} entries")
            updated_entries = []
            base_delta = self.image_base - new_base
            for entry in self.entries:
                new_address = int(entry[1], 16) - base_delta
                func_name = ida_funcs.get_func_name(new_address)
                block_name = ida_name.get_ea_name(new_address)
                if func_name == block_name:
                    new_name = func_name
                elif not func_name:
                    new_name = block_name
                else:
                    func_address = ida_name.get_name_ea(0, func_name)
                    new_name = func_name + ((":" + block_name) if block_name else f"+{new_address-func_address:x}")
                updated_entries.append([new_name, hex(new_address), entry[2], "", "", ""])
            self.update(updated_entries)
            self.image_base = new_base

    def set_breakpoints(self, func_list = None):
        if not func_list:
            func_list = self.entries
        for entry in func_list:
            new_bpt = ida_dbg.bpt_t()
            ida_dbg.add_bpt(int(entry[1], 16), 0, ida_idd.BPT_DEFAULT)
            ida_dbg.get_bpt(int(entry[1], 16), new_bpt)
            new_bpt.flags = ida_dbg.BPT_ENABLED
            ida_dbg.update_bpt(new_bpt)

    def remove_breakpoints(self, entries = None):
        if not entries:
            entries = range(len(self.entries))
        for entry in entries:
            ida_dbg.del_bpt(int(self.entries[entry][1], 16))

    def load_state(self):
        valid_states = [name for name in self.states]
        if not valid_states:
            print("[Code Filter] No states to load")
            return
        elif len(valid_states) == 1:
            self.state_name = valid_states[0]
        else:
            selected_name = self.dropdown_chooser(valid_states)
            self.state_name = valid_states[selected_name]
        self.remove_breakpoints()
        self.update(copy.deepcopy(self.states[self.state_name]["entries"]))
        self.image_base = self.states[self.state_name]["image_base"]
        self.process_relocations()
        self.set_breakpoints()

    def save_state(self):
        if not self.state_name:
            self.save_state_as()
            return
        self.states[self.state_name] = {"entries": copy.deepcopy(self.entries), "image_base": self.image_base}
        self.netnode.setblob(pickle.dumps(self.states), 0, "B")

    def save_state_as(self):
        new_state_name = ida_kernwin.ask_str("", 0, "Save state as ")
        self.states[new_state_name] = {"entries": copy.deepcopy(self.entries), "image_base": self.image_base}
        self.netnode.setblob(pickle.dumps(self.states), 0, "B")
        self.state_name = new_state_name

    def delete_state(self):
        if not self.state_name:
            print("[Code Filter] No state to delete")
            return
        del self.states[self.state_name]
        self.netnode.setblob(pickle.dumps(self.states), 0, "B")
        self.remove_breakpoints()
        self.state_name = ""
        self.update([])

    def dropdown_chooser(self, options):
        load_form = DropdownFormLoad(options)
        load_form.Compile()
        if load_form.Execute():
            selected = load_form.cbDropdown.value
        else:
            selected = None
        load_form.Free()
        return selected

    def start_function_search(self):
        new_entries = []
        for func_index in range(ida_funcs.get_func_qty()):
            func = ida_funcs.getn_func(func_index)
            new_entries.append([ida_funcs.get_func_name(func.start_ea), hex(func.start_ea), "False", "", "", ""])
        self.remove_breakpoints()
        self.update(new_entries)
        self.set_breakpoints()
        print(f"[Code Filter] Starting function search with {len(new_entries)} entries")

    def start_block_search(self, selected_entries):
        new_entries = []
        block_cache = []
        for selected_entry in selected_entries:
            func = ida_funcs.get_func(int(self.entries[selected_entry][1], 16))
            for block in ida_gdl.FlowChart(func):
                entry_name = ida_funcs.get_func_name(func.start_ea)
                block_name = ida_name.get_ea_name(block.start_ea)
                if block_name and block_name in block_cache:
                    continue
                block_cache.append(block_name)
                if entry_name != block_name:
                    entry_name += (":" + block_name) if block_name else f"+{block.start_ea-func.start_ea:x}"
                new_entries.append([entry_name, hex(block.start_ea), "False", "", "", ""])
        self.remove_breakpoints()
        self.update(new_entries)
        self.set_breakpoints()
        print(f"[Code Filter] Starting block search with {len(new_entries)} blocks")

    def remove_selected_entries(self, remove_entries):
        new_entries = []
        for index, entry in enumerate(self.entries):
            if index not in remove_entries:
                new_entries.append(entry)
        self.remove_breakpoints(remove_entries)
        self.update(new_entries)
        print(f"[Code Filter] Removing {len(remove_entries)} selected entries")

    def remove_executed_entries(self):
        current_entries = self.entries
        executed_entries = [current_entries.index(entry) for entry in current_entries if entry[2] == "True"]
        self.remove_breakpoints(executed_entries)
        self.update([entry for entry in current_entries if entry[2] == "False"])
        print(f"[Code Filter] Removing {len(executed_entries)} executed entries")

    def remove_unexecuted_entries(self):
        current_entries = self.entries
        unexecuted_entries = [current_entries.index(entry) for entry in current_entries if entry[2] == "False"]
        self.remove_breakpoints(unexecuted_entries)
        executed_entries = [entry for entry in current_entries if entry[2] == "True"]
        for entry in executed_entries:
            ida_dbg.enable_bpt(int(entry[1], 16))
            entry[2] = "False"
        self.update(executed_entries)
        print(f"[Code Filter] Removing {len(unexecuted_entries)} unexecuted entries")

    def clear_execution_count(self):
        for entry in self.entries:
            entry[4] = ""
        self.cf_chooser.Refresh()

    def enable_execution_count(self):
        self.execution_count_enabled = True
        self.cf_chooser.SetExecutionCount(True)

    def disable_execution_count(self):
        self.execution_count_enabled = False
        self.cf_chooser.SetExecutionCount(False)

    def function_window_add_function(self, functions):
        new_funcs = []
        existing_funcs = [entry[1] for entry in self.entries]
        for func_number in functions:
            func = ida_funcs.getn_func(func_number)
            if hex(func.start_ea) in existing_funcs:
                continue
            func_name = ida_funcs.get_func_name(func.start_ea)
            new_funcs.append([func_name, hex(func.start_ea), "False", "", "", ""])
        self.set_breakpoints(new_funcs)
        self.update(self.entries + new_funcs)

    def dbg_bpt(self, ea):
        for entry in self.entries:
            if entry[1] == hex(ea):
                entry[2] = "True"
                entry[3] = str(self.next_execution_index())
                if self.execution_count_enabled:
                    entry[4] = str(int(entry[4]) + 1) if entry[4] else "1"
                else:
                    ida_dbg.disable_bpt(ea)
                self.cf_chooser.Refresh()

    def dbg_process_start(self):
        self.process_relocations()
        for entry in self.entries:
            entry[3] = ""
        self.cf_chooser.Refresh()
        self.execution_index = 0

    def set_comment(self, comment_entries):
        comment = ida_kernwin.ask_str("", 0, "Set comment")
        for comment_entry in comment_entries:
            self.entries[comment_entry][5] = comment
        self.cf_chooser.Refresh()

class ChooserStartFunctionSearch(ida_kernwin.action_handler_t):

    def __init__(self, code_filter):
        self.code_filter = code_filter

    def activate(self, ctx):
        self.code_filter.start_function_search()
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

class ChooserStartBlockSearch(ida_kernwin.action_handler_t):

    def __init__(self, code_filter):
        self.code_filter = code_filter

    def activate(self, ctx):
        self.code_filter.start_block_search(ctx.chooser_selection)
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

class ChooserRemoveAllEntries(ida_kernwin.action_handler_t):

    def __init__(self, code_filter):
        self.code_filter = code_filter

    def activate(self, ctx):
        self.code_filter.remove_breakpoints()
        self.code_filter.update([])
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

class ChooserRemoveSelectedEntries(ida_kernwin.action_handler_t):

    def __init__(self, code_filter):
        self.code_filter = code_filter

    def activate(self, ctx):
        self.code_filter.remove_selected_entries(ctx.chooser_selection)
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

class ChooserRemoveExecutedEntries(ida_kernwin.action_handler_t):

    def __init__(self, code_filter):
        self.code_filter = code_filter

    def activate(self, ctx):
        self.code_filter.remove_executed_entries()
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

class ChooserRemoveUnexecutedEntries(ida_kernwin.action_handler_t):

    def __init__(self, code_filter):
        self.code_filter = code_filter

    def activate(self, ctx):
        self.code_filter.remove_unexecuted_entries()
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

class ChooserLoadState(ida_kernwin.action_handler_t):

    def __init__(self, code_filter):
        self.code_filter = code_filter

    def activate(self, ctx):
        self.code_filter.load_state()
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

class ChooserSaveState(ida_kernwin.action_handler_t):

    def __init__(self, code_filter):
        self.code_filter = code_filter

    def activate(self, ctx):
        self.code_filter.save_state()
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

class ChooserSaveStateAs(ida_kernwin.action_handler_t):

    def __init__(self, code_filter):
        self.code_filter = code_filter

    def activate(self, ctx):
        self.code_filter.save_state_as()
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

class ChooserDeleteState(ida_kernwin.action_handler_t):

    def __init__(self, code_filter):
        self.code_filter = code_filter

    def activate(self, ctx):
        self.code_filter.delete_state()
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

class ChooserSetComment(ida_kernwin.action_handler_t):

    def __init__(self, code_filter):
        self.code_filter = code_filter

    def activate(self, ctx):
        self.code_filter.set_comment(ctx.chooser_selection)
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

class ChooserEnableExecutionCount(ida_kernwin.action_handler_t):

    def __init__(self, code_filter):
        self.code_filter = code_filter

    def activate(self, ctx):
        self.code_filter.enable_execution_count()
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

class ChooserDisableExecutionCount(ida_kernwin.action_handler_t):

    def __init__(self, code_filter):
        self.code_filter = code_filter

    def activate(self, ctx):
        self.code_filter.disable_execution_count()
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

class ChooserClearExecutionCount(ida_kernwin.action_handler_t):

    def __init__(self, code_filter):
        self.code_filter = code_filter

    def activate(self, ctx):
        self.code_filter.clear_execution_count()
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

class FunctionWindowAddToCodeFilter(ida_kernwin.action_handler_t):

    def __init__(self, code_filter):
        self.code_filter = code_filter

    def activate(self, ctx):
        self.code_filter.function_window_add_function(ctx.chooser_selection)
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

class DebugHooks(ida_dbg.DBG_Hooks):

    def dbg_bpt(self, tid, ea):
        self.code_filter.dbg_bpt(ea)
        return 0

    def dbg_process_start(self, pid, tid, ea, modinfo_name, modinfo_base, modinfo_size):
        self.code_filter.dbg_process_start()
        return True

    def set_parent(self, code_filter):
        self.code_filter = code_filter

class UIHooks(ida_kernwin.UI_Hooks):

    def create_desktop_widget(self, ttl, cfg):
        print(f"[Code Filter] Creating desktop widget with title {ttl}")
        #if ttl == "Code Filter":
        #    self.code_filter.cf_chooser = CodeFilterChooser()
        #    self.code_filter.cf_chooser.Show()
        #    return self.code_filter.cf_chooser


    def finish_populating_widget_popup(self, widget, popup, ctx):
        if ctx.widget_type == ida_kernwin.BWN_FUNCS:
            ida_kernwin.attach_action_to_popup(ctx.widget, popup, "function_window_add_function", None, ida_kernwin.SETMENU_APP)

    def saving(self):
        self.breakpoint_cache = []
        for entry in self.code_filter.entries:
            new_bpt = ida_dbg.bpt_t()
            ida_dbg.get_bpt(int(entry[1], 16), new_bpt)
            self.breakpoint_cache.append([int(entry[1], 16), bool(new_bpt.flags & ida_dbg.BPT_ENABLED)])
        self.code_filter.remove_breakpoints()

    def saved(self):
        self.code_filter.set_breakpoints()
        for entry in self.breakpoint_cache:
            if not entry[1]:
                ida_dbg.disable_bpt(entry[0])

    def set_parent(self, code_filter):
        self.code_filter = code_filter

def PLUGIN_ENTRY():
    return CodeFilter()