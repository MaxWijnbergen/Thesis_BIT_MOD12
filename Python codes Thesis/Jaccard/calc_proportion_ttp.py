import re
from collections import defaultdict
# This code calculates a ratio that shows the percentage of a specific TTP being correlated to a specific CWE. It is calculated by dividing the intersection by the total of the TTP, so not by the union

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
            total_ttp = ttp_counts[ttp]
            total_cwe = cwe_counts[cwe]
            jaccard_index = intersection_count / total_ttp if total_ttp != 0 else 0
            jaccard_indices[(ttp, cwe)] = (jaccard_index, total_cwe, total_ttp)
    
    return jaccard_indices

def write_jaccard_indices(filepath, jaccard_indices):
    with open(filepath, 'w') as file:
        file.write("Jaccard Index Report\n")
        file.write("====================\n\n")
        
        for (ttp, cwe), (jaccard_index, total_cwe, total_ttp) in sorted(jaccard_indices.items(), key=lambda item: item[1][0], reverse=True):
            file.write(f"{ttp} - {cwe}: {jaccard_index:.4f} (Total CWE: {total_cwe}, Total TTP: {total_ttp})\n")

# Main process
input_filepath = 'summary_report_no_dups.txt'
output_filepath = 'proportion_indices_ttp.txt'

data = read_file(input_filepath)
ttp_counts, cwe_counts, ttp_cwe_mapping = parse_summary_report(data)
jaccard_indices = calculate_jaccard(ttp_counts, cwe_counts, ttp_cwe_mapping)
write_jaccard_indices(output_filepath, jaccard_indices)

print("Jaccard index report generated. The results are saved to", output_filepath)