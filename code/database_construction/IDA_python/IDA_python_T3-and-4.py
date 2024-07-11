import idautils
import ida_funcs
import idc
import ida_bytes
import ida_lines
import json

arch_name= "x64" # adjust this arch_name according to the specific ISA
binary_name = idc.get_root_filename()
key_byte_code = f"byte_code_{arch_name}"
key_pse_code = f"pseudocode_{arch_name}"

functions_data = []

for segea in idautils.Segments():
    segname = idc.get_segm_name(segea)
    if segname == '.text':
        for func_ea in idautils.Functions(segea, idc.get_segm_end(segea)):
            func = ida_funcs.get_func(func_ea)
            if func:
                func_name = idc.get_func_name(func_ea)
                func_offset = func.start_ea
                func_length = ida_funcs.calc_func_size(func)
                byte_code = ""
                for head in idautils.Heads(func.start_ea, func.end_ea):
                    bytes = ida_bytes.get_bytes(head, idc.get_item_size(head))
                    bytes_str = ' '.join(['{:02X}'.format(b) for b in bytes])
                    disasm = idc.generate_disasm_line(head, 0)
                    #disasm = idc.tag_remove(disasm)
                    byte_code += "0x{:08X} | {} | {}\n".format(head, bytes_str, disasm)
                pseudocode = ""
                try:
                    cfunc = idaapi.decompile(func_ea)
                    if not cfunc:
                        print(f"Failed to decompile function at {hex(func_ea)}. Continuing to next function.")
                        continue
                    pseudocode = ida_lines.tag_remove(cfunc.__str__())
                except ida_hexrays.DecompilationFailure as e:
                    print(f"Decompilation failed at {hex(func_ea)} with error: {e}")
                    continue
                
                functions_data.append({
                    "func_name": func_name,
                    "func_offset": "0x{:08X}".format(func_offset),
                    "func_length": func_length,
                    key_byte_code: byte_code.strip(),
                    key_pse_code: pseudocode
                })

json_filename = f"{binary_name}_{arch_name}.json"

with open(json_filename, 'w') as outfile:
    json.dump(functions_data, outfile, indent=4)

print("JSON file has been created with the functions' data.")

