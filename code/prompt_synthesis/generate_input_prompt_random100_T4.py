import json
import random

data_num = 100

with open('Retrieved_busybox_from_busybox.json', 'r', errors='ignore') as file:
    func_combined_data = json.load(file)

print("num of funcs before filtering: ", len(func_combined_data))

filtered_data = [
    item for item in func_combined_data
    if 5 < item['pseudocode_stripped'].count('\n') < 100 and item['source_code'] is not None
]

print("num of funcs after filtering: ", len(filtered_data))

# Just shuffle! 
random.shuffle(filtered_data)


selected_data = filtered_data


with open('./prompt_texts/suffix.txt', 'r') as file:
    suffix = file.read()

prompt_len_limit = 12000


## RAG detail prompt

with open('./prompt_texts/prompt_test_stripped_RAG_withDetail.txt', 'r') as file:
    prompt_content_RAG_detail = file.read()

count = 0
new_json_data = []

for item in selected_data:

    final_prompt = prompt_content_RAG_detail

    func_name = item['func_name']

    if func_name == item["top_11_close_funcs_pse_stripped"][0][0]:
        top3_close_func_names = [pair[0] for pair in item["top_11_close_funcs_pse_stripped"][1:4]]
    else:
        top3_close_func_names = [pair[0] for pair in item["top_11_close_funcs_pse_stripped"][0:3]]

    print(top3_close_func_names)

    for top_func_name in top3_close_func_names:
        #print('Matching: ', top_func_name)
        matched_item = next(item_t for item_t in func_combined_data if item_t.get('func_name') == top_func_name)

        if matched_item['source_code'] is None:
            print('ATTENTION! Empty source code')
        final_prompt = final_prompt + "\n\n## Example:\n\n Input code:\n" + matched_item['pseudocode_stripped'] + "\n\n Revised code:\n" + matched_item['source_code']
        
    #print("Prompt construction finished.\n******************")
    final_prompt = final_prompt + suffix + item['pseudocode_stripped']

    # Skip too long prompts
    if len(final_prompt)>prompt_len_limit:
        continue
    
    print("len of this prompt (restricted within 8000):", len(final_prompt))

    new_item = {
        "func_name": item['func_name'],
        "model_input": final_prompt
    }
    new_json_data.append(new_item)
    count += 1
    if count >= data_num:
        break

with open('input_prompt_T7_stripped_RAG_withDetail.json', 'w') as file:
    json.dump(new_json_data, file, indent=4)



################################


## RAG prompt

with open('./prompt_texts/prompt_test_stripped_RAG.txt', 'r') as file:
    prompt_content_RAG_detail = file.read()

count = 0
new_json_data = []

for item in selected_data:

    final_prompt = prompt_content_RAG_detail

    func_name = item['func_name']

    if func_name == item["top_11_close_funcs_pse_stripped"][0][0]:
        top3_close_func_names = [pair[0] for pair in item["top_11_close_funcs_pse_stripped"][1:4]]
    else:
        top3_close_func_names = [pair[0] for pair in item["top_11_close_funcs_pse_stripped"][0:3]]

    print(top3_close_func_names)

    for top_func_name in top3_close_func_names:
        #print('Matching: ', top_func_name)
        matched_item = next(item_t for item_t in func_combined_data if item_t.get('func_name') == top_func_name)

        if matched_item['source_code'] is None:
            print('ATTENTION! Empty source code')
        final_prompt = final_prompt + "\n\n## Example:\n\n Input code:\n" + matched_item['pseudocode_stripped'] + "\n\n Revised code:\n" + matched_item['source_code']
        
    #print("Prompt construction finished.\n******************")
    final_prompt = final_prompt + suffix + item['pseudocode_stripped']

    # Skip too long prompts
    if len(final_prompt)>prompt_len_limit:
        continue
    
    print("len of this prompt (restricted within 8000):", len(final_prompt))

    new_item = {
        "func_name": item['func_name'],
        "model_input": final_prompt
    }
    new_json_data.append(new_item)
    count += 1
    if count >= data_num:
        break

with open('input_prompt_T7_stripped_RAG.json', 'w') as file:
    json.dump(new_json_data, file, indent=4)




###########################

## detail prompt

with open('./prompt_texts/prompt_test_stripped_withDetail.txt', 'r') as file:
    prompt_content_RAG_detail = file.read()

count = 0
new_json_data = []

for item in selected_data:

    final_prompt = prompt_content_RAG_detail

    func_name = item['func_name']

    final_prompt = final_prompt + suffix + item['pseudocode_stripped']

    # Skip too long prompts
    if len(final_prompt)>prompt_len_limit:
        continue
    
    print("len of this prompt (restricted within 8000):", len(final_prompt))

    new_item = {
        "func_name": item['func_name'],
        "model_input": final_prompt
    }
    new_json_data.append(new_item)
    count += 1
    if count >= data_num:
        break

with open('input_prompt_T7_stripped_withDetail.json', 'w') as file:
    json.dump(new_json_data, file, indent=4)



###########################

## Naive prompt

with open('./prompt_texts/prompt_test_stripped_naive.txt', 'r') as file:
    prompt_content_RAG_detail = file.read()

count = 0
new_json_data = []

for item in selected_data:

    final_prompt = prompt_content_RAG_detail

    func_name = item['func_name']

    final_prompt = final_prompt + suffix + item['pseudocode_stripped']

    # Skip too long prompts
    if len(final_prompt)>prompt_len_limit:
        continue
    
    print("len of this prompt (restricted within 8000):", len(final_prompt))

    new_item = {
        "func_name": item['func_name'],
        "model_input": final_prompt
    }
    new_json_data.append(new_item)
    count += 1
    if count >= data_num:
        break

with open('input_prompt_T7_stripped_naive.json', 'w') as file:
    json.dump(new_json_data, file, indent=4)



print("Data written")

