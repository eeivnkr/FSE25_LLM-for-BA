import idautils
import ida_segment
import ida_funcs
import idc
import json

n=200

binary_name = idc.get_root_filename()

text_seg = ida_segment.get_segm_by_name(".text")

all_func_starts = set(idautils.Functions(text_seg.start_ea, text_seg.end_ea))

segments_data = []
current_segment = {"offset_start": "", "assembly_data": "", "func_starts": set()}
instruction_count = 0

for ea in idautils.Heads(text_seg.start_ea, text_seg.end_ea):
    if ea in all_func_starts:
        current_segment["func_starts"].add(hex(ea))

    instruction = "{} | {}\n".format(hex(ea), idc.generate_disasm_line(ea, 0))
    
    if instruction_count == 0:
        current_segment["offset_start"] = hex(ea)
    
    current_segment["assembly_data"] += instruction
    instruction_count += 1

    if instruction_count >= n:
        segments_data.append(current_segment)
        current_segment = {"offset_start": "", "assembly_data": "", "func_starts": set()}
        instruction_count = 0

if instruction_count > 0:
    segments_data.append(current_segment)


for segment in segments_data:
    segment["func_starts"] = list(segment["func_starts"])

json_filename = f"{binary_name}_n{n}.json"
with open(json_filename, "w") as json_file:
    json.dump(segments_data, json_file, indent=4)

print("full json length: ", len(segments_data))

print(f"Data saved to {json_filename}")


