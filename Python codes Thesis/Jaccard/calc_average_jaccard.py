# Read the files
with open('jaccard_indices_final_no_dup.txt', 'r') as file:
    lines_no_dup = file.readlines()

with open('jaccard_indices_final_one_cwe.txt', 'r') as file:
    lines_one_cwe = file.readlines()

# Extract Jaccard indices
def extract_indices(lines):
    indices = []
    for line in lines:
        if ':' in line:
            parts = line.split(':')
            if len(parts) > 2:
                try:
                    index = float(parts[2].split()[0])
                    indices.append(index)
                except ValueError:
                    continue
    return indices

indices_no_dup = extract_indices(lines_no_dup)
indices_one_cwe = extract_indices(lines_one_cwe)

# Calculate the average
avg_no_dup = sum(indices_no_dup) / len(indices_no_dup) if indices_no_dup else 0
avg_one_cwe = sum(indices_one_cwe) / len(indices_one_cwe) if indices_one_cwe else 0

# Insert the average at the top
lines_no_dup.insert(0, f'Average Jaccard Index: {avg_no_dup:.4f}\n')
lines_one_cwe.insert(0, f'Average Jaccard Index: {avg_one_cwe:.4f}\n')

# Save the updated files
with open('jaccard_indices_final_no_dup.txt', 'w') as file:
    file.writelines(lines_no_dup)

with open('jaccard_indices_final_one_cwe.txt', 'w') as file:
    file.writelines(lines_one_cwe)

# Provide the download links for the updated files
print("Files updated successfully.")