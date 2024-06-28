
ttp_file_path = 'C:/Users/Gebruiker/Downloads/Python codes Thesis/Jaccard/proportion_indices_ttp.txt'
cwe_file_path = 'C:/Users/Gebruiker/Downloads/Python codes Thesis/Jaccard/proportion_indices_cwe.txt'
output_file_path = 'C:/Users/Gebruiker/Downloads/average_indices.txt'

# Read the contents of the files
with open(ttp_file_path, 'r') as file:
    ttp_content = file.readlines()

with open(cwe_file_path, 'r') as file:
    cwe_content = file.readlines()

# Function to extract indices from content
def extract_indices(content):
    indices = {}
    for line in content:
        parts = line.strip().split(": ")
        if len(parts) > 2:
            try:
                key = f"{parts[0].strip()}: {parts[1].strip()}"
                index = float(parts[2].split()[0])
                indices[key] = index
            except ValueError:
                print(f"Skipping line due to value error: {line}")
    return indices

# Extract indices from both files
ttp_indices = extract_indices(ttp_content)
cwe_indices = extract_indices(cwe_content)

# Calculate average indices for each common key
average_indices = {}
for key in ttp_indices:
    if key in cwe_indices:
        average_indices[key] = (ttp_indices[key] + cwe_indices[key]) / 2

# Calculate the overall average of all the results
if average_indices:
    overall_average = sum(average_indices.values()) / len(average_indices)
else:
    overall_average = 0

# Write the overall average and the results to a new file
with open(output_file_path, 'w') as file:
    file.write(f"Overall Average: {overall_average:.4f}\n\n")
    for key, avg in sorted(average_indices.items()):
        file.write(f"{key}: {avg:.4f}\n")

print(f"Average indices and overall average written to {output_file_path}")