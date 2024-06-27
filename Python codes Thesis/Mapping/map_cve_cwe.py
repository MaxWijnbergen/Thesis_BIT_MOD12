import re
# This code maps the CVEs to the CWEs. A file is used from NVD containing the existing correlations between CVEs and CWEs. This code goes through the  found CVEs and checks for every CVE if it is in the "cve_cwe_mappings.txt" file and if it is, it takes the corresponding CWE and writes the correlations to a new file called "matched_cve_cwe.txt"

# Define function to read the contents of a file
def read_file(file_path):
    with open(file_path, 'r', encoding='utf-8') as file:
        return file.readlines()

# Function to check CVE IDs in the CVE file against the CWE file and print CWE ID if found
def check_cves(cve_file, cwe_file, output_file):
    cve_lines = read_file(cve_file)
    cwe_lines = read_file(cwe_file)

    # Create a dictionary to store CWE IDs for each CVE ID from the cwe_file
    cve_to_cwe = {}

    # Populate the dictionary with CVE-CWE mappings
    for cwe_line in cwe_lines:
        match = re.search(r'(CVE-\d{4}-\d+).*?(CWE-\d+)', cwe_line)
        if match:
            cve_id = match.group(1)
            cwe_id = match.group(2)
            cve_to_cwe[cve_id] = cwe_id

    # Prepare the output content
    output_content = []
    processed_cves = set()
    current_header = None

    # Check each line in the CVE file
    for cve_line in cve_lines:
        # Check if the line is a header
        if cve_line.startswith('CVEs found in'):
            # If there is a current header, add a newline before adding a new header
            if current_header is not None:
                output_content.append('\n')
            current_header = cve_line.strip()
            output_content.append(current_header + '\n')
        else:
            cve_matches = re.findall(r'(CVE-\d{4}-\d+)', cve_line)
            for cve_id in cve_matches:
                if cve_id not in processed_cves:
                    if cve_id in cve_to_cwe:
                        cwe_id = cve_to_cwe[cve_id]
                        output_content.append(f'{cve_id}: {cwe_id}\n')
                    else:
                        output_content.append(f'{cve_id}: No CWE found\n')
                    processed_cves.add(cve_id)

    # Write the output to the file
    with open(output_file, 'w', encoding='utf-8') as output:
        output.writelines(output_content)

# Define file paths
cve_file_path = 'all_found_cves.txt'  # Adjust the path as needed
cwe_file_path = 'cve_cwe_mappings.txt'  # Ensure this path is correct
output_file_path = 'matched_cve_cwe.txt'  # Adjust the path as needed

# Execute the function
check_cves(cve_file_path, cwe_file_path, output_file_path)