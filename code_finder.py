import ida_kernwin
import ida_idaapi
import ida_funcs
import ida_name
import ida_gdl
import ida_dbg
import ida_idd
import idc

import ida_nalt


class CodeFinderChooser(ida_kernwin.Choose):

    selected_entries = []

    def __init__(self, entries):

        super().__init__(
            "CodeFinder",
            [["Name", 20], ["Address", 20], ["Executed", 10]],
            flags = ida_kernwin.CH_MULTI | ida_kernwin.CH_KEEP
        )

        CodeFinderChooser.entries = entries

    def OnGetSize(self):
        return len(CodeFinderChooser.entries)

    def OnGetLine(self, n):
        return CodeFinderChooser.entries[n]

    def OnSelectLine(self, n):
        ida_kernwin.jumpto(int(CodeFinderChooser.entries[n[0]][1], 16))
        
    def OnSelectionChange(self, selected):
        CodeFinderChooser.selected_entries = selected

    def OnPopup(self, widget, popup_handle):

        ida_kernwin.attach_action_to_popup(
            widget,
            popup_handle,
            "chooser_start_function_search",
            None,
            ida_kernwin.SETMENU_APP
        )

        ida_kernwin.attach_action_to_popup(
            widget,
            popup_handle,
            "chooser_start_block_search",
            None,
            ida_kernwin.SETMENU_APP
        )

        ida_kernwin.attach_action_to_popup(
            widget,
            popup_handle,
            "chooser_remove_all_entries",
            None,
            ida_kernwin.SETMENU_APP
        )

        ida_kernwin.attach_action_to_popup(
            widget,
            popup_handle,
            "chooser_remove_selected_entries",
            None,
            ida_kernwin.SETMENU_APP
        )

        ida_kernwin.attach_action_to_popup(
            widget,
            popup_handle,
            "chooser_remove_executed_entries",
            None,
            ida_kernwin.SETMENU_APP
        )

        ida_kernwin.attach_action_to_popup(
            widget,
            popup_handle,
            "chooser_remove_unexecuted_entries",
            None,
            ida_kernwin.SETMENU_APP
        )

    @classmethod
    def GetSelectedEntries(cls):
        return cls.selected_entries

class CodeFinder(ida_idaapi.plugin_t):
    """
    Plugin that uses breakpoints to find executed and non executed functions or blocks
    """
    flags = ida_idaapi.PLUGIN_MOD
    comment = "This plugin implements functionality similar to cheat engine's code block finding"
    help = "Plugin that uses breakpoints to find executed and non executed functions or blocks"
    wanted_name = "Code Finder"
    wanted_hotkey = "Ctrl-Shift-C"

    entries = []
    image_base = None

    def init(self):

        CodeFinder.image_base = ida_nalt.get_imagebase()
        self.cf_bp_hook = BreakpointHook()
        self.cf_bp_hook.hook()

        ida_kernwin.register_action(
            ida_kernwin.action_desc_t(
                "chooser_start_function_search",
                "Start Function Search",
                ChooserStartFunctionSearch()
            )
        )

        ida_kernwin.register_action(
            ida_kernwin.action_desc_t(
                "chooser_start_block_search",
                "Start Block Search",
                ChooserStartBlockSearch()
            )
        )

        ida_kernwin.register_action(
            ida_kernwin.action_desc_t(
                "chooser_remove_all_entries",
                "Remove All Entries",
                ChooserRemoveAllEntries()
            )
        )

        ida_kernwin.register_action(
            ida_kernwin.action_desc_t(
                "chooser_remove_selected_entries",
                "Remove Selected Entries",
                ChooserRemoveSelectedEntries()
            )
        )

        ida_kernwin.register_action(
            ida_kernwin.action_desc_t(
                "chooser_remove_executed_entries",
                "Remove Executed Entries",
                ChooserRemoveExecutedEntries()
            )
        )

        ida_kernwin.register_action(
            ida_kernwin.action_desc_t(
                "chooser_remove_unexecuted_entries",
                "Remove Unexecuted Entries",
                ChooserRemoveUnexecutedEntries()
            )
        )

        print("[Code Finder] Plugin initialized")

        return ida_idaapi.PLUGIN_KEEP


    def run(self, arg):

        self.cf_chooser = CodeFinderChooser(CodeFinder.entries)
        self.cf_chooser.Show()

        print("[Code Finder] Plugin executed")

        return ida_idaapi.PLUGIN_OK

    def term(self):
        print("[Code Finder] Plugin terminated")

    @classmethod
    def SetBreakpoints(cls):
        for entry in CodeFinder.entries:
            new_bpt = ida_dbg.bpt_t()
            ida_dbg.add_bpt(int(entry[1], 16), 0, ida_idd.BPT_DEFAULT)
            ida_dbg.get_bpt(int(entry[1], 16), new_bpt)
            new_bpt.flags = idc.BPT_ENABLED
            ida_dbg.update_bpt(new_bpt)

    @classmethod
    def RemoveBreakpoints(cls, entries):
        for entry in entries:
            ida_dbg.del_bpt(int(CodeFinder.entries[entry][1], 16))

class ChooserStartFunctionSearch(ida_kernwin.action_handler_t):

    def activate(self, ctx):
        new_entries = []
        for func_index in range(ida_funcs.get_func_qty()):
            func = ida_funcs.getn_func(func_index)
            new_entries.append([ida_funcs.get_func_name(func.start_ea), hex(func.start_ea), "False"])
        CodeFinder.RemoveBreakpoints(range(len(CodeFinder.entries)))
        CodeFinder.entries = new_entries
        CodeFinder.SetBreakpoints()
        print(f"[Code Finder] Starting function search with {len(new_entries)} entries")
        CodeFinder.cf_chooser = CodeFinderChooser(CodeFinder.entries)
        CodeFinder.cf_chooser.Show()
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

class ChooserStartBlockSearch(ida_kernwin.action_handler_t):

    def activate(self, ctx):
        new_entries = []
        block_cache = []
        for func_index in range(ida_funcs.get_func_qty()):
            func = ida_funcs.getn_func(func_index)
            for block in ida_gdl.FlowChart(func):
                entry_name = ida_funcs.get_func_name(func.start_ea)
                block_name = ida_name.get_ea_name(block.start_ea)
                if block_name and block_name in block_cache:
                    continue
                block_cache.append(block_name)
                if entry_name != block_name:
                    entry_name += (":" + block_name) if block_name else f"+{block.start_ea-func.start_ea:x}"
                new_entries.append([entry_name, hex(block.start_ea), "False"])
        CodeFinder.RemoveBreakpoints(range(len(CodeFinder.entries)))
        CodeFinder.entries = new_entries
        CodeFinder.SetBreakpoints()
        print(f"[Code Finder] Starting block search with {len(new_entries)} blocks")
        CodeFinder.cf_chooser = CodeFinderChooser(CodeFinder.entries)
        CodeFinder.cf_chooser.Show()
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

class ChooserRemoveAllEntries(ida_kernwin.action_handler_t):

    def activate(self, ctx):
        CodeFinder.RemoveBreakpoints(range(len(CodeFinder.entries)))
        CodeFinder.entries = []
        print("[Code Finder] Removing all entries")
        CodeFinder.cf_chooser = CodeFinderChooser(CodeFinder.entries)
        CodeFinder.cf_chooser.Show()
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

class ChooserRemoveSelectedEntries(ida_kernwin.action_handler_t):

    def activate(self, ctx):
        new_entries = []
        remove_entries = CodeFinderChooser.GetSelectedEntries()
        for index in range(len( CodeFinder.entries)):
            if index not in remove_entries:
                new_entries.append(CodeFinder.entries[index])
        CodeFinder.RemoveBreakpoints(remove_entries)
        CodeFinder.entries = new_entries
        print(f"[Code Finder] Removing {len(remove_entries)} selected entries")
        CodeFinder.cf_chooser = CodeFinderChooser(CodeFinder.entries)
        CodeFinder.cf_chooser.Show()
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

class ChooserRemoveExecutedEntries(ida_kernwin.action_handler_t):

    def activate(self, ctx):
        executed_entries = [index for index in range(len(CodeFinder.entries)) if CodeFinder.entries[index][2] == "True"]
        CodeFinder.RemoveBreakpoints(executed_entries)
        CodeFinder.entries = [entry for entry in CodeFinder.entries if entry[2] == "False"]
        print(f"[Code Finder] Removing {len(executed_entries)} executed entries")
        CodeFinder.cf_chooser = CodeFinderChooser(CodeFinder.entries)
        CodeFinder.cf_chooser.Show()
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

class ChooserRemoveUnexecutedEntries(ida_kernwin.action_handler_t):

    def activate(self, ctx):
        CodeFinder.RemoveBreakpoints(range(len(CodeFinder.entries)))
        unexecuted_entries = [entry for entry in CodeFinder.entries if entry[2] == "False"]
        CodeFinder.entries = [entry for entry in CodeFinder.entries if entry[2] == "True"]
        for entry in CodeFinder.entries:
            entry[2] = "False"
        CodeFinder.SetBreakpoints()
        print(f"[Code Finder] Removing {len(unexecuted_entries)} unexecuted entries")
        CodeFinder.cf_chooser = CodeFinderChooser(CodeFinder.entries)
        CodeFinder.cf_chooser.Show()
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

class BreakpointHook(ida_dbg.DBG_Hooks):

    def dbg_bpt(self, tid, ea):
        for entry in CodeFinder.entries:
            if entry[1] == hex(ea):
                entry[2] = "True"
                ida_dbg.disable_bpt(ea)
        return 0

    def dbg_process_start(self, pid, tid, ea, modinfo_name, modinfo_base, modinfo_size):
        new_base = ida_nalt.get_imagebase()
        orig_base = CodeFinder.image_base
        if new_base != orig_base:
            current_entries = CodeFinder.entries
            print(f"[Code Finder] Image base changed from {orig_base:#x} to {new_base:#x}, updating {len(current_entries)} entries")
            updated_entries = []
            base_delta = orig_base - new_base
            for entry in current_entries:
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
                updated_entries.append([new_name, hex(new_address), entry[2]])
            CodeFinder.entries = updated_entries
            CodeFinder.image_base = new_base
            CodeFinder.cf_chooser = CodeFinderChooser(CodeFinder.entries)
            CodeFinder.cf_chooser.Show()
        return True

def PLUGIN_ENTRY():
    return CodeFinder()