import re
import json
import torch
import argparse
from transformers import RobertaTokenizer, RobertaConfig, RobertaModel

import torch.nn.functional as F


def cosine_similarity(vector1, vector2):
    cos_sim = F.cosine_similarity(vector1, vector2, dim=1)
    return cos_sim.item()


def parse_args():
    parser = argparse.ArgumentParser(description='Evaluate LLM decompilation output')
    parser.add_argument('--data_path', default='data.json')
    parser.add_argument('--json_path', default='busybox_full.json')
    parser.add_argument('--model_path')
    parser.add_argument('--output_path')
    args = parser.parse_args()
    return args

args = parse_args()


MAX_TOKEN_LEN = 1024

tokenizer = RobertaTokenizer.from_pretrained("./unixcoder-base-nine/unixcoder-base-nine", model_max_length=MAX_TOKEN_LEN)
model = RobertaModel.from_pretrained("./unixcoder-base-nine/unixcoder-base-nine")

with open(args.json_path, 'r', errors='ignore') as file:
    full_gt_json = json.load(file)

with open(args.data_path, 'r', errors='ignore') as file:
    llm_output_json = json.load(file)


sim_score_list = []
sim_score_stripped_list = []
sim_score_debug_list = []


for item in llm_output_json:
    #print("(" + str(count+1) + "/" + str(full_length) + ")")
    func_name = item['func_name']

    try:
        matched_item = next(item_t for item_t in full_gt_json if item_t.get('func_name') == func_name)
        print("Found matched func.")
    except StopIteration:
        print("No matched func found.")

    revised_code = item['output']
    source_code = matched_item['source_code']
    if source_code is None:
        print('Empty source code! \n *************************')
        item['source_code'] = None
        item['parsed_output'] = None
        item['similarity_score_unixcoder'] = None
        continue

    ida_pseCode_stripped = matched_item['pseudocode_stripped']
    ida_pseCode_debug = matched_item['pseudocode']

    pattern = r"```c(.*?)```"
    match = re.search(pattern, revised_code, re.DOTALL)

    if match is None:
        pass
    else:
        revised_code = match.group(1).strip()

    sentences = [revised_code, source_code, ida_pseCode_stripped, ida_pseCode_debug]
    encoded_input = tokenizer(sentences, padding=True, truncation=True, max_length=MAX_TOKEN_LEN, return_tensors='pt')

    #encoded_input = [ seq[:MAX_TOKEN_LEN] if len(seq)>MAX_TOKEN_LEN for seq in encoded_input]

    with torch.no_grad():
        model_output = model(**encoded_input)

    sentence_embeddings = [i.unsqueeze(dim=0) for i in model_output.pooler_output]

    similarity = cosine_similarity(sentence_embeddings[0], sentence_embeddings[1])
    similarity_ida_strippted_to_source = cosine_similarity(sentence_embeddings[1], sentence_embeddings[2])
    similarity_ida_debug_to_source = cosine_similarity(sentence_embeddings[1], sentence_embeddings[3])

    sim_score_list.append(similarity)
    sim_score_stripped_list.append(similarity_ida_strippted_to_source)
    sim_score_debug_list.append(similarity_ida_debug_to_source)

    item['source_code'] = source_code
    item['parsed_output'] = revised_code
    item['baseline_code_stripped'] = ida_pseCode_stripped
    item['baseline_code_debug'] = ida_pseCode_debug
    item['similarity_score_unixcoder'] = similarity
    item['similarity_score_baseline_stripped'] = similarity_ida_strippted_to_source
    item['similarity_score_baseline_debug'] = similarity_ida_debug_to_source

    print('func_name: ', func_name)
    print('------')
    print('source_code: ', source_code)
    print('------')
    print('revised_code: ', revised_code)
    print('------')
    print('similarity score: ', similarity)
    print('------')
    print('baseline score stripped: ', similarity_ida_strippted_to_source)
    print('------')
    print('baseline score debug: ', similarity_ida_debug_to_source)
    print('*************************')

with open(args.data_path.replace('.json', '_unixcoder_scored.json'), 'w') as file:
    json.dump(llm_output_json, file, indent=4)


print("Avg score: ", sum(sim_score_list)/len(sim_score_list))
print("Avg score baseline stripped: ", sum(sim_score_stripped_list)/len(sim_score_stripped_list))
print("Avg score baseline debug: ", sum(sim_score_debug_list)/len(sim_score_debug_list))

