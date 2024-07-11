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
    parser = argparse.ArgumentParser(description='Retrieve top10 closest functions, based on generated embedding and input original json')
    parser.add_argument('--data_path', default='./busybox_full.json')
    # The embedding database TO BE RETRIEVED
    parser.add_argument('--embed_path', default='./busybox_embedding.pt')
    parser.add_argument('--model_path')
    parser.add_argument('--output_path', default='./output_json_top10')
    args = parser.parse_args()
    return args

args = parse_args()


MAX_TOKEN_LEN = 1024

tokenizer = RobertaTokenizer.from_pretrained("/data/home/pengfeijing/LLM_for_BA/code_similarity/unixcoder-base-nine/unixcoder-base-nine", model_max_length=MAX_TOKEN_LEN)
model = RobertaModel.from_pretrained("/data/home/pengfeijing/LLM_for_BA/code_similarity/unixcoder-base-nine/unixcoder-base-nine")

with open(args.data_path, 'r', errors='ignore') as file:
    full_gt_json = json.load(file)


# Load stored embeddings of each function
loaded_embeddings = torch.load(args.embed_path)

count = 0

retrieved_top11_json = []

for item in full_gt_json:
    query_func_name = item['func_name']
    print(query_func_name)
    pseudocode_stripped = item['pseudocode_x64']
    if pseudocode_stripped is None:
        print("No pse code! continue")
        count += 1
        continue    

    # Search func data from original full data json
    try:
        matched_item = next(item_t for item_t in full_gt_json if item_t.get('func_name') == query_func_name)
        print("Found matched func.")
    except StopIteration:
        print("No matched func found.")

    query_pse_stripped_code = matched_item['pseudocode_x64']
    sentences = [query_pse_stripped_code]
    encoded_input = tokenizer(sentences, padding=True, truncation=True, max_length=MAX_TOKEN_LEN, return_tensors='pt')
    
    with torch.no_grad():
        model_output = model(**encoded_input)

    sentence_embeddings = [i.unsqueeze(dim=0) for i in model_output.pooler_output]
    anchor_embedding = sentence_embeddings[0]

    sim_scores = []

    for queried_func_name in loaded_embeddings:
        queried_func_embedding = loaded_embeddings[queried_func_name]['pse_stripped_embedding']
        cos_distance = cosine_similarity(anchor_embedding, queried_func_embedding)
        sim_score_pair = [queried_func_name, cos_distance]
        sim_scores.append(sim_score_pair)


    # Sort by similarity score
    sorted_sim_score = sorted(sim_scores, key=lambda x: x[1], reverse=True)
    
    matched_item['top_11_close_funcs_pse_stripped'] = sorted_sim_score[:11]

    retrieved_top11_json.append(matched_item)

    count += 1
    print("(" + str(count+1) + "/" + str(len(full_gt_json)) + ")")
    print('************')


with open(args.output_path, 'w', encoding='utf-8') as json_file:
    json.dump(retrieved_top11_json, json_file, ensure_ascii=False, indent=4)


