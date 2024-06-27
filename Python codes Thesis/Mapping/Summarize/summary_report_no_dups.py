import re
from collections import defaultdict, Counter
# This code summarizes the found correlations in the text files. For every TTP it counts the amount of times it is correlated to every CWE  and it is the same for the CWE. For every CWE it counts the amount times it is correlated to every TTP. It also Counts the amount of every TTP in the file and the amount of every CWE in the file. It is the same code as summary_report_one_cwe.py

def read_file(filepath):
    with open(filepath, 'r') as file:
        data = file.read()
    return data

def extract_articles(data):
    articles = re.split(r'(CVEs found in \w+\.txt:)', data)
    articles = ["".join(i) for i in zip(articles[1::2], articles[2::2])]
    return articles

def extract_ttp_cwe(article):
    lines = article.strip().split('\n')
    ttps = []
    cwes = []
    for line in lines:
        if line.startswith('TTP:'):
            ttps.append(line)
        elif line.startswith('CWE-'):
            cwes.append(line)
    return ttps, cwes

def generate_summary(articles):
    ttp_counter = Counter()
    cwe_counter = Counter()
    ttp_cwe_map = defaultdict(Counter)
    
    for article in articles:
        ttps, cwes = extract_ttp_cwe(article)
        ttp_counter.update(ttps)
        cwe_counter.update(cwes)
        for ttp in ttps:
            ttp_cwe_map[ttp].update(cwes)
    
    return ttp_counter, cwe_counter, ttp_cwe_map

def write_summary(filepath, ttp_counter, cwe_counter, ttp_cwe_map):
    with open(filepath, 'w') as file:
        file.write("Summary Report\n")
        file.write("=================\n\n")
        
        file.write("Top TTPs:\n")
        for ttp, count in ttp_counter.most_common():
            file.write(f"{ttp}: {count}\n")
        file.write("\n")
        
        file.write("Top CWEs:\n")
        for cwe, count in cwe_counter.most_common():
            file.write(f"{cwe}: {count}\n")
        file.write("\n")
        
        file.write("TTP to CWE mapping:\n")
        for ttp, cwe_counter in ttp_cwe_map.items():
            file.write(f"{ttp}:\n")
            for cwe, count in cwe_counter.most_common():
                file.write(f"  {cwe}: {count}\n")
            file.write("\n")

# Main process
input_filepath = r'C:\Users\Gebruiker\Downloads\filtered_matched_no_dups.txt'
output_filepath = 'summary_report_no_dups.txt'

data = read_file(input_filepath)
articles = extract_articles(data)
ttp_counter, cwe_counter, ttp_cwe_map = generate_summary(articles)
write_summary(output_filepath, ttp_counter, cwe_counter, ttp_cwe_map)

print("Summary report generated. The results are saved to", output_filepath)