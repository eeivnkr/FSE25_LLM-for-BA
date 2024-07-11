import argparse
import json
import csv
import openai
import os
import pandas as pd
import requests
import time

waiting_time = 45
waiting_gap = 5

def parse_args():
    parser = argparse.ArgumentParser(description='Run LLM Evaluation')
    parser.add_argument('--api_key', default='your-API-key')
    parser.add_argument('--api_endpoint', default='your-endpoint')
    parser.add_argument('--api_type', default='type')
    parser.add_argument('--api_version', default='version')
    parser.add_argument('--deployment_name', default='your-gpt')
    parser.add_argument('--input_dir', default='./gpt4_input', help='input directory')
    parser.add_argument('--output_dir', default='./gpt4_output', help='output directory' )
    args = parser.parse_args()
    return args


def main():
    args = parse_args()

    # Set openai parameters
    openai.api_key = args.api_key
    openai.api_base = args.api_endpoint
    openai.api_type = args.api_type
    openai.api_version = args.api_version

    # Start processing all input files
    filenames = os.listdir(args.input_dir)
    for filename in filenames:
        # Read input file
        src_path = os.path.join(args.input_dir, filename)
        with open(src_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        results = []

        for i, item in enumerate(data):
            # Get result from GPT model
            
            model_input = item['model_input']

            print('current file: ', filename)
            print("(" + str(i+1) + "/" + str(len(data)) + ")")
            if (i % waiting_gap == 0) and (i>1):
                print('Waiting...')
                time.sleep(waiting_time)
            print("Processing...")

            chat_completion = openai.ChatCompletion.create(
                    messages=[{
                    "role": "user",
                    "content": model_input
                    }],
                    deployment_id=args.deployment_name,
                    temperature=0,  # default 0
                    request_timeout=1000
            )
            model_output = chat_completion.choices[0].message.content if chat_completion else ''

            print('gpt output: ', model_output)
            print('**********************************')

            results.append({
                'func_name': item['func_name'],
                'input': model_input,
                'output': model_output
                })

        # Write results to .csv file
        #df = pd.DataFrame(results)
        #dst_path = os.path.join(args.output_dir, filename.split('.')[0] + '.csv')
        #df.to_csv(dst_path, encoding='utf-8-sig', quoting=1, sep=',')

        # Write results to json
        dst_path = os.path.join(args.output_dir, filename.split('.')[0] + '.json')
        with open(dst_path, 'w', encoding='utf-8') as json_file:
            json.dump(results, json_file, ensure_ascii=False, indent=4)


if __name__ == '__main__':
    main()

