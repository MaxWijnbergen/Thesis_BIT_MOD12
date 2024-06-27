import os
import re
# This code goes through all CTI files and finds all CVEs and writes them to a new file called "all_found_cves.txt". First go through the directory_path to check if it exists or the wrong directory path is taken. Then it goes through all text files in the directory path and reads the file, if a CVE is found it will be added to the array and checked if it is a unique CVE. After going through all files, the CVEs are printed to the new file.


# Directory containing the text files
directory_path = 'C:\\Users\\Gebruiker\\Downloads\\cti'  # Adjust the path as needed

# Function to extract and print CVEs from the text files
def extract_cves(directory_path):
    print(f"Searching in directory: {directory_path}")
    if not os.path.exists(directory_path):
        print(f"Directory does not exist: {directory_path}")
        return

    all_results = []
    
    for filename in os.listdir(directory_path):
        if filename.endswith('.txt'):
            file_path = os.path.join(directory_path, filename)
            print(f"Processing file: {file_path}")
            
            # Read the file content
            try:
                with open(file_path, 'r', encoding='utf-8') as file:
                    article_text = file.read()
            except Exception as e:
                print(f"Error reading file {file_path}: {e}")
                continue
            
            # Find CVEs
            cve_matches = re.findall(r'CVE-\d{4}-\d+', article_text)
            unique_cves = list(set(cve_matches))
            
            if unique_cves:
                results = [f"CVEs found in {filename}:"]
                for cve in unique_cves:
                    results.append(f"  CVE: {cve}")
                all_results.append('\n'.join(results))  # Join the results as a single string
                all_results.append("")  # Add a blank line for separation
            else:
                print(f"No CVEs found in {filename}")

    # Write all results to a single file
    output_file_path = os.path.join(directory_path, "all_found_cves.txt")
    try:
        with open(output_file_path, 'w', encoding='utf-8') as file:
            for result in all_results:
                file.write(result + "\n")
        print(f"Results written to {output_file_path}")
    except Exception as e:
        print(f"Error writing to file {output_file_path}: {e}")

# Run the function
extract_cves(directory_path)