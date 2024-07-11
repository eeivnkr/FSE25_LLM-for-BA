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
    parser = argparse.ArgumentParser(description='Generate unixcoder embedding based on input json')
    parser.add_argument('--data_path', default='busybox_full.json')
    parser.add_argument('--model_path')
    parser.add_argument('--output_path', default='./busybox_embedding.pt')
    args = parser.parse_args()
    return args

args = parse_args()


MAX_TOKEN_LEN = 1024

tokenizer = RobertaTokenizer.from_pretrained("./unixcoder-base-nine/unixcoder-base-nine", model_max_length=MAX_TOKEN_LEN)
model = RobertaModel.from_pretrained("./unixcoder-base-nine/unixcoder-base-nine")

with open(args.data_path, 'r', errors='ignore') as file:
    full_gt_json = json.load(file)


parsed_RAG_embedding = {}
count = 0

for item in full_gt_json:
    source_code = item['source_code']
    if source_code is None:
        print('Empty source code! \n *************************')
        continue
    print("(" + str(count+1) + "/" + str(len(full_gt_json)) + ")")
    print('Parsing: ', item["func_name"])
    psecode_stripped = item["pseudocode_stripped"]
    if psecode_stripped is None:
        print('Empty psecode_stripped code! \n *************************')
        continue
    sentences = [psecode_stripped]
    encoded_input = tokenizer(sentences, padding=True, truncation=True, max_length=MAX_TOKEN_LEN, return_tensors='pt')
    
    with torch.no_grad():
        model_output = model(**encoded_input)

    sentence_embeddings = [i.unsqueeze(dim=0) for i in model_output.pooler_output]
    dict_to_store = {'pse_stripped_embedding':sentence_embeddings[0]}
    parsed_RAG_embedding[item["func_name"]] = dict_to_store
    count += 1


torch.save(parsed_RAG_embedding, args.output_path)

