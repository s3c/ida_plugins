import ida_kernwin
import ida_idaapi
import ida_name
import ida_xref
import ida_bytes
import ida_nalt
import ida_funcs

class CFGViewerChooser(ida_kernwin.Choose):

    def __init__(self):

        super().__init__(
            "CFG Viewer",
            [["Name", 50], ["Address", 15], ["Type", 30]],
            flags = ida_kernwin.CH_MULTI | ida_kernwin.CH_KEEP
        )

        self.entries = []

    def OnGetSize(self):
        return len(self.entries)

    def OnGetLine(self, n):
        return self.entries[n]

    def OnSelectLine(self, n):
        ida_kernwin.jumpto(int(self.entries[n[0]][1], 16))

    def OnPopup(self, widget, popup_handle):

        ida_kernwin.attach_action_to_popup(widget, popup_handle, "chooser_highlight_entries", None, ida_kernwin.SETMENU_APP)

    def Update(self, entries):
        self.entries = entries
        self.Refresh()

class CFGViewer(ida_idaapi.plugin_t):

    flags = ida_idaapi.PLUGIN_MOD
    comment = "This plugin shows specifics about the entries in the CFG GFIDS table"
    help = "This plugin shows specifics about the entries in the CFG GFIDS table"
    wanted_name = "CFG Viewer"
    wanted_hotkey = "Ctrl-Shift-D"

    def init(self):

        self.entries = []

        ida_kernwin.register_action(ida_kernwin.action_desc_t("chooser_highlight_entries", "Highlight Entries", CFGViewerHighlightEntries(self)))

        print("[Code Filter] Plugin initialized")

        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg):

        if not self.entries:
            self.entries = self.parse_cfg_table()
            self.cfg_viewer_chooser = CFGViewerChooser()
            self.cfg_viewer_chooser.Update(self.entries)
        self.cfg_viewer_chooser.Show()

        print("[Code Filter] Plugin executed")

        return ida_idaapi.PLUGIN_OK

    def term(self):

        print("[CFG Viewer] Plugin terminated")

    def parse_cfg_table(self):

        IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK = 0xF0000000
        IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_SHIFT = 28

        IMAGE_GUARD_FLAG_FID_SUPPRESSED = 1
        IMAGE_GUARD_FLAG_EXPORT_SUPPRESSED = 2
        IMAGE_GUARD_FLAG_FID_LANGEXCPTHANDLER = 4
        IMAGE_GUARD_FLAG_FID_XFG = 8

        # Go add GuardAddressTakenIatEntryTable - __guard_iat_table
        # Go add GuardLongJumpTargetTable - __guard_longjmp_table

        cfg_entries = []
        guard_fids_table_addr = ida_name.get_name_ea(0, "__guard_fids_table")
        if guard_fids_table_addr != ida_idaapi.BADADDR:
            guard_fids_table_count_addr = ida_xref.get_first_dref_to(guard_fids_table_addr) + 8
            guard_fids_table_count = ida_bytes.get_qword(guard_fids_table_count_addr)
            guard_flags_addr = guard_fids_table_count_addr + 8
            guard_flags = ida_bytes.get_dword(guard_flags_addr)
            info_length = (guard_flags & IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK) >> IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_SHIFT
            for i in range(guard_fids_table_count):
                cfg_entry_addr = guard_fids_table_addr + (i * 4) + (i * info_length)
                cfg_addr = ida_bytes.get_dword(cfg_entry_addr) + ida_nalt.get_imagebase()
                cfg_type = "Allowed"
                function_name = ida_funcs.get_func_name(cfg_addr)
                if info_length:
                    cfg_addr_info = int.from_bytes(ida_bytes.get_bytes(cfg_entry_addr + 4, info_length))
                    if cfg_addr_info & IMAGE_GUARD_FLAG_FID_SUPPRESSED:
                        cfg_type = "Suppressed"
                    elif cfg_addr_info & IMAGE_GUARD_FLAG_EXPORT_SUPPRESSED:
                        cfg_type = "Export Suppressed"
                    elif cfg_addr_info & IMAGE_GUARD_FLAG_FID_LANGEXCPTHANDLER:
                        cfg_type = "Language Exception Handler"
                    elif cfg_addr_info & IMAGE_GUARD_FLAG_FID_XFG:
                        cfg_type = "XFG Enabled"
                cfg_entries.append([function_name, hex(cfg_addr), cfg_type])

        return cfg_entries

    def highlight_entries(self):

        for cfg_entry in self.entries:
            cfg_addr = int(cfg_entry[1], 16)
            if cfg_entry[2] == "Allowed":
                type_color = 0xBBFFAA
            elif cfg_entry[2] == "Suppressed":
                type_color = 0x0055FF
            elif cfg_entry[2] == "Export Suppressed":
                type_color = 0x00FF55
            elif cfg_entry[2] == "Language Exception Handler":
                type_color = 0xFFAA00
            for byte_addr in range(cfg_addr, cfg_addr + 16):
                ida_nalt.set_item_color(byte_addr, type_color)

class CFGViewerHighlightEntries(ida_kernwin.action_handler_t):

    def __init__(self, code_filter):
        self.code_filter = code_filter

    def activate(self, ctx):
        self.code_filter.highlight_entries()
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

def PLUGIN_ENTRY():
    return CFGViewer()