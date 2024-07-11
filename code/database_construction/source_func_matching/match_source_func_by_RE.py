import re
import sys
import json


def extract_function_from_all_code(code, function_name):

    function_pattern = re.compile(
    r'(\b\w+\b\s+|\*)+\b' + re.escape(function_name) + r'\b\s*\([^)]*\)\s*{',
    re.DOTALL)

    print("Try matching function: ", function_name)

    match = function_pattern.search(code)

    if not match:
        print(f"Function '{function_name}' not found.")
        return
    
    print("Function matched.")

    start_index = match.start()

    open_braces_count = 0
    function_body = ''
    for i in range(start_index, len(code)):
        if code[i] == '{':
            open_braces_count += 1
        elif code[i] == '}':
            open_braces_count -= 1

        function_body += code[i]

        if open_braces_count == 0 and code[i] == '}':
            break

    if open_braces_count != 0:
        print("Error: Braces are not balanced in the function body.")
        return

    return function_body


def extract_function_from_file(file_path, function_name):
    with open(file_path, 'r', errors='ignore') as file:
        code = file.read()

    function_pattern = re.compile(
    r'(\b\w+\b\s+)+(?:\s*\*)?\b' + re.escape(function_name) + r'\b\s*\([^)]*\)\s*{',
    re.DOTALL)

    print("Try matching function: ", function_name)

    match = function_pattern.search(code)

    if not match:
        print(f"Function '{function_name}' not found.")
        return
    
    print("Function matched.")

    start_index = match.start()

    open_braces_count = 0
    function_body = ''
    for i in range(start_index, len(code)):
        if code[i] == '{':
            open_braces_count += 1
        elif code[i] == '}':
            open_braces_count -= 1

        function_body += code[i]

        if open_braces_count == 0 and code[i] == '}':
            break

    if open_braces_count != 0:
        print("Error: Braces are not balanced in the function body.")
        return

    return function_body



if __name__ == "__main__":

    with open('json_produced_by_IDA_python.json', 'r') as file:
        full_json = json.load(file)

    with open('merged_source_code.c', 'r', errors='ignore') as file:
        code_file = file.read()

    count = 0
    full_length = len(full_json)

    for item in full_json:
        print("(" + str(count+1) + "/" + str(full_length) + ")")
        func_name = item['func_name']
        found_source_code = extract_function_from_all_code(code_file, func_name)
        item['source_code'] = found_source_code
        count += 1

    with open('json_source_func_matched.json', 'w') as file:
        json.dump(full_json, file, indent=4)

    print("Json with source function matched saved as json_source_func_matched.json")

