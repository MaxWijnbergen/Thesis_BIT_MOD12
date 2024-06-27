import re
from collections import defaultdict
# This code calculates the Jaccard index for the summary file with one cwe for every text file. It counts the total of the specific TTP, of the specific CWE and the intersection and calculates the Jaccard index accordingly

def read_file(filepath):
    with open(filepath, 'r') as file:
        data = file.read()
    return data

def parse_summary_report(data):
    ttp_counts = {}
    cwe_counts = {}
    ttp_cwe_mapping = defaultdict(dict)
    
    lines = data.strip().split('\n')
    mode = None
    current_ttp = None
    
    for line in lines:
        line = line.strip()
        
        if line.startswith('Top TTPs:'):
            mode = 'ttp'
            continue
        elif line.startswith('Top CWEs:'):
            mode = 'cwe'
            continue
        elif line.startswith('TTP to CWE mapping:'):
            mode = 'mapping'
            continue
        
        if mode == 'ttp' and line:
            ttp, count = line.rsplit(': ', 1)
            ttp = ttp.strip(': ')
            ttp_counts[ttp] = int(count)
        
        elif mode == 'cwe' and line:
            cwe, count = line.rsplit(': ', 1)
            cwe = cwe.strip(': ')
            cwe_counts[cwe] = int(count)
        
        elif mode == 'mapping' and line:
            if re.match(r'TTP:', line):
                current_ttp = line.strip(': ')
            else:
                cwe, count = line.split(': ')
                cwe = cwe.strip(': ')
                ttp_cwe_mapping[current_ttp][cwe] = int(count)
    
    return ttp_counts, cwe_counts, ttp_cwe_mapping

def calculate_jaccard(ttp_counts, cwe_counts, ttp_cwe_mapping):
    jaccard_indices = {}
    
    for ttp, cwe_map in ttp_cwe_mapping.items():
        ttp = ttp.strip(': ')  # Ensure TTP key is stripped correctly
        for cwe, intersection_count in cwe_map.items():
            cwe = cwe.strip(': ')  # Ensure CWE key is stripped correctly
            if ttp not in ttp_counts:
                print(f"TTP not found in ttp_counts: '{ttp}'")
                continue
            if cwe not in cwe_counts:
                print(f"CWE not found in cwe_counts: '{cwe}'")
                continue
            union_count = cwe_counts[cwe] + ttp_counts[ttp] - intersection_count
            jaccard_index = intersection_count / union_count if union_count != 0 else 0
            jaccard_indices[(ttp, cwe)] = (jaccard_index, cwe_counts[cwe], ttp_counts[ttp])
    
    return jaccard_indices

def write_jaccard_indices(filepath, jaccard_indices):
    with open(filepath, 'w') as file:
        file.write("Jaccard Index Report\n")
        file.write("====================\n\n")
        
        for (ttp, cwe), (jaccard_index, cwe_total, ttp_total) in sorted(jaccard_indices.items(), key=lambda item: item[1][0], reverse=True):
            file.write(f"{ttp} - {cwe}: {jaccard_index:.4f} (CWE Total: {cwe_total}, TTP Total: {ttp_total})\n")

# Main process
input_filepath = 'summary_report_one_cwe.txt'
output_filepath = 'jaccard_indices_final_one_cwe.txt'

data = read_file(input_filepath)
ttp_counts, cwe_counts, ttp_cwe_mapping = parse_summary_report(data)
jaccard_indices = calculate_jaccard(ttp_counts, cwe_counts, ttp_cwe_mapping)
write_jaccard_indices(output_filepath, jaccard_indices)

print("Jaccard index report generated. The results are saved to", output_filepath)