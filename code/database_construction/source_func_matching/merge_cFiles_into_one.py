import os
import sys

def find_c_files(folder_path):
    c_files = []
    for root, dirs, files in os.walk(folder_path):
        for file in files:
            if file.endswith('.c'):
                full_path = os.path.join(root, file)
                c_files.append(full_path)
    return c_files

def combine_c_files(c_files, output_file='combined.c'):
    with open(output_file, 'w', encoding='utf-8', errors='ignore') as outfile:
        for c_file in c_files:
            with open(c_file, 'r', encoding='utf-8', errors='ignore') as infile:
                outfile.write(f"// Contents of {c_file}\n")
                outfile.write(infile.read())
                outfile.write("\n\n")

def main():
    if len(sys.argv) != 2:
        print("Usage: python combine_c_files.py <folder_path>")
        sys.exit(1)
    
    folder_path = sys.argv[1]
    c_files = find_c_files(folder_path)
    combine_c_files(c_files)
    print(f"All .c files have been combined into {os.path.abspath('combined.c')}")

if __name__ == "__main__":
    main()