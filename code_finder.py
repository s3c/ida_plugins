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

class CodeFinderChooser(ida_kernwin.Choose):

    def __init__(self):

        super().__init__(
            "Code Finder",
            [["Name", 20], ["Address", 20], ["Executed", 10], ["Execution Index", 10], ["Comment", 10]],
            flags = ida_kernwin.CH_MULTI | ida_kernwin.CH_KEEP
        )

        self.selected_entries = []
        self.entries = []

    def OnGetSize(self):
        return len(self.entries)

    def OnGetLine(self, n):
        return self.entries[n]

    def OnSelectLine(self, n):
        ida_kernwin.jumpto(int(self.entries[n[0]][1], 16))
        
    def OnSelectionChange(self, selected):
        self.selected_entries = selected

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
        ida_kernwin.attach_action_to_popup(widget, popup_handle, "chooser_set_comment", None, ida_kernwin.SETMENU_ENSURE_SEP)

    def Update(self, entries):
        self.entries = entries
        self.Refresh()

    def GetSelectedEntries(self):
        return self.selected_entries

class DropdownFormLoad(ida_kernwin.Form):

    def __init__(self, options):

        form_layout = "STARTITEM 0\n" \
                      "BUTTON YES* Load\n" \
                      "BUTTON CANCEL Cancel\n" \
                      "Load State\n" \
                      "<State :{cbDropdown}>"

        ida_kernwin.Form.__init__(self, form_layout, {'cbDropdown': ida_kernwin.Form.DropdownListControl(items=options)})

class CodeFinder(ida_idaapi.plugin_t):

    flags = ida_idaapi.PLUGIN_MOD
    comment = "This plugin implements functionality similar to cheat engine's code block finding"
    help = "Plugin that uses breakpoints to find executed and non executed functions or blocks"
    wanted_name = "Code Finder"
    wanted_hotkey = "Ctrl-Shift-C"

    def init(self):

        self.cf_chooser = CodeFinderChooser()

        self.cf_bp_hook = DebugHook()
        self.cf_bp_hook.set_parent(self)

        self.ui_hooks = UIHooks()
        self.ui_hooks.set_parent(self)

        self.execution_count = 0
        self.image_base = ida_nalt.get_imagebase()
        self.state_name = ""
        self.entries = []
        self.states = {}

        self.netnode = ida_netnode.netnode("CodeFinderNode", 0, True)
        netnode_blob = self.netnode.getblob(0, "B")
        if netnode_blob:
            self.states = pickle.loads(netnode_blob)

        ida_kernwin.register_action(ida_kernwin.action_desc_t("chooser_start_function_search","Start Function Search", ChooserStartFunctionSearch(self)))
        ida_kernwin.register_action(ida_kernwin.action_desc_t("chooser_start_block_search","Start Block Search", ChooserStartBlockSearch(self)))
        ida_kernwin.register_action(ida_kernwin.action_desc_t("chooser_remove_all_entries","Remove All Entries", ChooserRemoveAllEntries(self)))
        ida_kernwin.register_action(ida_kernwin.action_desc_t("chooser_remove_selected_entries","Remove Selected Entries", ChooserRemoveSelectedEntries(self)))
        ida_kernwin.register_action(ida_kernwin.action_desc_t("chooser_remove_executed_entries","Remove Executed Entries", ChooserRemoveExecutedEntries(self)))
        ida_kernwin.register_action(ida_kernwin.action_desc_t("chooser_remove_unexecuted_entries","Remove Unexecuted Entries", ChooserRemoveUnexecutedEntries(self)))
        ida_kernwin.register_action(ida_kernwin.action_desc_t("chooser_load_state","Load State", ChooserLoadState(self)))
        ida_kernwin.register_action(ida_kernwin.action_desc_t("chooser_save_state","Save State", ChooserSaveState(self)))
        ida_kernwin.register_action(ida_kernwin.action_desc_t("chooser_save_state_as","Save State as", ChooserSaveStateAs(self)))
        ida_kernwin.register_action(ida_kernwin.action_desc_t("chooser_delete_state", "Delete State", ChooserDeleteState(self)))
        ida_kernwin.register_action(ida_kernwin.action_desc_t("chooser_set_comment", "Set Comment", ChooserSetComment(self)))

        print("[Code Finder] Plugin initialized")

        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg):

        self.ui_hooks.hook()
        self.cf_bp_hook.hook()
        self.cf_chooser.Show()

        print("[Code Finder] Plugin executed")

        return ida_idaapi.PLUGIN_OK

    def term(self):

        print("[Code Finder] Plugin terminated")

    def update(self, entries):
        self.entries = entries
        self.cf_chooser.Update(self.entries)

    def next_execution_count(self):
        self.execution_count += 1
        return self.execution_count

    def process_relocations(self):
        new_base = ida_nalt.get_imagebase()
        if new_base != self.image_base:
            print(f"[Code Finder] Image base changed from {self.image_base:#x} to {new_base:#x}, updating {len(self.entries)} entries")
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
                updated_entries.append([new_name, hex(new_address), entry[2], "", ""])
            self.update(updated_entries)
            self.image_base = new_base

    def set_breakpoints(self):
        for entry in self.entries:
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
            print("[Code Finder] No states to load")
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
            print("[Code Finder] No state to delete")
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
            new_entries.append([ida_funcs.get_func_name(func.start_ea), hex(func.start_ea), "False", "", ""])
        self.remove_breakpoints()
        self.update(new_entries)
        self.set_breakpoints()
        print(f"[Code Finder] Starting function search with {len(new_entries)} entries")

    def start_block_search(self):
        new_entries = []
        block_cache = []
        selected_entries = self.cf_chooser.GetSelectedEntries()
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
                new_entries.append([entry_name, hex(block.start_ea), "False", "", ""])
        self.remove_breakpoints()
        self.update(new_entries)
        self.set_breakpoints()
        print(f"[Code Finder] Starting block search with {len(new_entries)} blocks")

    def remove_all_entries(self):
        self.remove_breakpoints()
        self.update([])
        print("[Code Finder] Removing all entries")

    def remove_selected_entries(self):
        new_entries = []
        remove_entries = self.cf_chooser.GetSelectedEntries()
        for index, entry in enumerate(self.entries):
            if index not in remove_entries:
                new_entries.append(entry)
        self.remove_breakpoints(remove_entries)
        self.update(new_entries)
        print(f"[Code Finder] Removing {len(remove_entries)} selected entries")

    def remove_executed_entries(self):
        current_entries = self.entries
        executed_entries = [current_entries.index(entry) for entry in current_entries if entry[2] == "True"]
        self.remove_breakpoints(executed_entries)
        self.update([entry for entry in current_entries if entry[2] == "False"])
        print(f"[Code Finder] Removing {len(executed_entries)} executed entries")

    def remove_unexecuted_entries(self):
        current_entries = self.entries
        unexecuted_entries = [current_entries.index(entry) for entry in current_entries if entry[2] == "False"]
        self.remove_breakpoints(unexecuted_entries)
        executed_entries = [entry for entry in current_entries if entry[2] == "True"]
        for entry in executed_entries:
            ida_dbg.enable_bpt(int(entry[1], 16))
            entry[2] = "False"
        self.update(executed_entries)
        print(f"[Code Finder] Removing {len(unexecuted_entries)} unexecuted entries")

    def dbg_bpt(self, ea):
        for entry in self.entries:
            if entry[1] == hex(ea):
                entry[2] = "True"
                entry[3] = str(self.next_execution_count())
                ida_dbg.disable_bpt(ea)

    def dbg_process_start(self):
        self.process_relocations()
        for entry in self.entries:
            entry[3] = ""
        self.execution_count = 0

    def set_comment(self):
        comment_entries = self.cf_chooser.GetSelectedEntries()
        comment = ida_kernwin.ask_str("", 0, "Set comment")
        for comment_entry in comment_entries:
            self.entries[comment_entry][4] = comment
        self.cf_chooser.Update(self.entries)

class ChooserStartFunctionSearch(ida_kernwin.action_handler_t):

    def __init__(self, code_finder):
        self.code_finder = code_finder

    def activate(self, ctx):
        self.code_finder.start_function_search()
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

class ChooserStartBlockSearch(ida_kernwin.action_handler_t):

    def __init__(self, code_finder):
        self.code_finder = code_finder

    def activate(self, ctx):
        self.code_finder.start_block_search()
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

class ChooserRemoveAllEntries(ida_kernwin.action_handler_t):

    def __init__(self, code_finder):
        self.code_finder = code_finder

    def activate(self, ctx):
        self.code_finder.remove_all_entries()
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

class ChooserRemoveSelectedEntries(ida_kernwin.action_handler_t):

    def __init__(self, code_finder):
        self.code_finder = code_finder

    def activate(self, ctx):
        self.code_finder.remove_selected_entries()
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

class ChooserRemoveExecutedEntries(ida_kernwin.action_handler_t):

    def __init__(self, code_finder):
        self.code_finder = code_finder

    def activate(self, ctx):
        self.code_finder.remove_executed_entries()
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

class ChooserRemoveUnexecutedEntries(ida_kernwin.action_handler_t):

    def __init__(self, code_finder):
        self.code_finder = code_finder

    def activate(self, ctx):
        self.code_finder.remove_unexecuted_entries()
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

class ChooserLoadState(ida_kernwin.action_handler_t):

    def __init__(self, code_finder):
        self.code_finder = code_finder

    def activate(self, ctx):
        self.code_finder.load_state()
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

class ChooserSaveState(ida_kernwin.action_handler_t):

    def __init__(self, code_finder):
        self.code_finder = code_finder

    def activate(self, ctx):
        self.code_finder.save_state()
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

class ChooserSaveStateAs(ida_kernwin.action_handler_t):

    def __init__(self, code_finder):
        self.code_finder = code_finder

    def activate(self, ctx):
        self.code_finder.save_state_as()
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

class ChooserDeleteState(ida_kernwin.action_handler_t):

    def __init__(self, code_finder):
        self.code_finder = code_finder

    def activate(self, ctx):
        self.code_finder.delete_state()
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

class ChooserSetComment(ida_kernwin.action_handler_t):

    def __init__(self, code_finder):
        self.code_finder = code_finder

    def activate(self, ctx):
        self.code_finder.set_comment()
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

class DebugHook(ida_dbg.DBG_Hooks):

    def dbg_bpt(self, tid, ea):
        self.code_finder.dbg_bpt(ea)
        return 0

    def dbg_process_start(self, pid, tid, ea, modinfo_name, modinfo_base, modinfo_size):
        self.code_finder.dbg_process_start()
        return True

    def set_parent(self, code_finder):
        self.code_finder = code_finder

class UIHooks(ida_kernwin.UI_Hooks):
    def saving(self):
        self.code_finder.remove_breakpoints()
        return super().saving()

    def set_parent(self, code_finder):
        self.code_finder = code_finder

def PLUGIN_ENTRY():
    return CodeFinder()