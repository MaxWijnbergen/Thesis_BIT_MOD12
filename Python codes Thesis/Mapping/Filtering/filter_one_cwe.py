import re
from collections import Counter
# This code filters out all CWEs for every text file except the one that has been encountered in that file the most amount of times.

# Function to read the file
def read_file(filepath):
    with open(filepath, 'r') as file:
        data = file.read()
    return data

# Function to extract articles
def extract_articles(data):
    articles = re.split(r'(CVEs found in \w+\.txt:)', data)
    articles = ["".join(i) for i in zip(articles[1::2], articles[2::2])]
    return articles

# Function to extract CWEs from an article
def extract_cwes(article):
    cwe_pattern = re.compile(r'CWE-\d+')
    return cwe_pattern.findall(article)

# Function to count CWEs in articles
def count_cwes(articles):
    cwe_counts = []
    for article in articles:
        cwes = extract_cwes(article)
        cwe_counter = Counter(cwes)
        cwe_counts.append(cwe_counter)
    return cwe_counts

# Function to find all the most common CWEs in a counter
def most_common_cwes(cwe_counter):
    if not cwe_counter:
        return []
    max_count = max(cwe_counter.values())
    return [cwe for cwe, count in cwe_counter.items() if count == max_count]

# Function to keep only the TTP lines and the most common CWEs
def keep_most_common_cwes(article, most_common_cwes):
    lines = article.split('\n')
    filtered_lines = []
    cwes_added = False
    for line in lines:
        if 'TTP:' in line or 'CVEs found in' in line:
            filtered_lines.append(line)
        elif any(cwe in line for cwe in most_common_cwes) and not cwes_added:
            filtered_lines.extend(most_common_cwes)
            cwes_added = True
    return '\n'.join(filtered_lines)

# Function to write the results to a new file
def write_to_file(filepath, articles):
    with open(filepath, 'w') as file:
        file.write("\n\n".join(articles))

# Main process
filepath = 'filtered_matched_cve_cwe_ttp.txt'
data = read_file(filepath)
articles = extract_articles(data)
cwe_counts = count_cwes(articles)
most_common_cwes_list = [most_common_cwes(counter) for counter in cwe_counts]
filtered_articles = [keep_most_common_cwes(article, cwes) for article, cwes in zip(articles, most_common_cwes_list)]

# Write the filtered articles to a new file
output_filepath = 'filtered_matched_cve_one_cwe_ttp.txt'
write_to_file(output_filepath, filtered_articles)

print("Filtering completed. The results are saved to", output_filepath)