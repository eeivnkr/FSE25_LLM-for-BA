import idautils
import idc
import json

def extract_segment_data(segment_name="text"):
    segment = idautils.Segments()
    for seg in segment:
        if segment_name in idc.get_segm_name(seg):
            start = idc.get_segm_start(seg)
            end = idc.get_segm_end(seg)
            segment_data = idc.get_bytes(start, end-start)
            return segment_data, start
    return None, None

def format_data_to_blocks(segment_data, start_address, line_length=16, lines_per_block=5):
    formatted_blocks = []
    bytes_per_block = line_length * lines_per_block
    for i in range(0, len(segment_data), bytes_per_block):
        block = segment_data[i:i+bytes_per_block]
        block_str = ""
        block_bytes_str = ""  
        for line in range(lines_per_block):
            line_data = block[line*line_length:(line+1)*line_length]
            if not line_data:
                break
            line_addr = start_address + i + line*line_length
            line_str = f"{line_addr:08X}  " + ' '.join([f"{byte:02X}" for byte in line_data[:8]]) + "  " + ' '.join([f"{byte:02X}" for byte in line_data[8:]])
            block_bytes_str += ' '.join([f"{byte:02X}" for byte in line_data])
            if line < lines_per_block - 1:
                block_str += line_str + "\n"
                block_bytes_str += " "
            else:
                block_str += line_str
        formatted_blocks.append((f"{start_address + i:08X}", block_str, block_bytes_str))
    return formatted_blocks

def disassemble_block(block, base_addr):
    assembly_data = {}
    offset = 0
    while offset < len(block):
        ea = base_addr + offset
        insn = idautils.DecodeInstruction(ea)
        if insn is None:
            offset += 1
            continue
        asm_line = idc.generate_disasm_line(ea, 0)
        byte_code = ' '.join([f"{x:02X}" for x in idc.get_bytes(ea, insn.size)])
        assembly_data[f"0x{ea:X}"] = f"{byte_code} - {asm_line}"
        offset += insn.size
    return assembly_data

def main():
    segment_data, base_address = extract_segment_data("text")
    if segment_data is None:
        print("Text segment not found.")
        return
    
    formatted_blocks = format_data_to_blocks(segment_data, base_address)
    data_pairs = []

    for start_addr_hex, block_str, block_bytes_str in formatted_blocks:
        block_address = int(start_addr_hex, 16)
        assembly_data = disassemble_block(idc.get_bytes(block_address, 80), block_address)
        data_pair = {
            "offset_start": start_addr_hex,
            "raw_code": block_str,
            "raw_code_only_bytes": block_bytes_str,
            "assembly_data": assembly_data
        }
        data_pairs.append(data_pair)
    
    with open("disassembly_output_3-14.json", "w") as f:
        json.dump(data_pairs, f, indent=4)

if __name__ == "__main__":
    main()

