import os
import requests
from bs4 import BeautifulSoup
# This code goes through the files and reads the text to see if any words or phrases match with the names of the TTPs. If so,
# the TTP is written to a new file called "matched_cve_cwe_ttp.txt". With help of the Python AI, developed by OpenAI, the function scrape_mitre_data()
# is created. The function gets the url for both the tactics page and the techniques page and goes through the IDs in the first column and the names in
# the second column. Then find_data_ids() goes through the text files and finds words or phrases that match the names in the second column on the tactics
# page and the techniques page. If they correspond then the TTP ID is taken and written to the new file

# Function to scrape MITRE ATT&CK techniques and their IDs
def scrape_mitre_data(url):
    response = requests.get(url)
    soup = BeautifulSoup(response.content, 'html.parser')

    table = soup.find('table')
    rows = table.find_all('tr')[1:]  # Skip the header row

    data = {}
    for row in rows:
        columns = row.find_all('td')
        data_id = columns[0].text.strip()
        data_name = columns[1].text.strip()
        data[data_name.lower()] = data_id

    return data

# Function to search for techniques and tactics in the text and return corresponding IDs
def find_data_ids(text, data):
    found_data = {}
    for data_name, data_id in data.items():
        if data_name in text.lower():
            found_data[data_name] = data_id
    return found_data

# Scrape techniques and tactics and their IDs
techniques_url = 'https://attack.mitre.org/techniques/enterprise/'
tactics_url = 'https://attack.mitre.org/tactics/enterprise/'
techniques = scrape_mitre_data(techniques_url)
tactics = scrape_mitre_data(tactics_url)

# Combine techniques and tactics into a single dictionary
mitre_data = {**techniques, **tactics}

# Path to the directory containing text files
directory_path = 'C:\\Users\\Gebruiker\\Downloads\\cti'  # Adjust the path as needed
input_file_path = os.path.join(directory_path, 'matched_cve_cwe.txt')  # Existing file
new_output_file_path = os.path.join(directory_path, 'matched_cve_cwe_ttp.txt')  # New output file

# Read the matched_cve_cwe.txt content
with open(input_file_path, 'r', encoding='utf-8') as file:
    lines = file.readlines()

# Create a new content list to store the updated lines
new_content = []

# Debugging: List the contents of the directory
print(f"Debug: Listing contents of {directory_path}")
dir_contents = os.listdir(directory_path)
for item in dir_contents:
    print(f"Directory item: '{item}'")

for line in lines:
    new_content.append(line)
    # Check if the line indicates the start of a new file section
    if line.startswith('CVEs found in'):
        filename = line.split(' ')[-1].strip().strip(':')  # Extract the filename and remove any trailing colons
        file_path = os.path.join(directory_path, filename)
        
        # Debugging statements
        print(f"Debug: Original line: '{line.strip()}'")
        print(f"Debug: Extracted filename: '{filename}'")
        print(f"Debug: Constructed file path: '{file_path}'")
        
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                article_text = file.read()
            print(f"Debug: Successfully read file: {file_path}")  # Debug print
        except FileNotFoundError:
            print(f"Debug: File not found: {file_path}")  # Debug print
            new_content.append("No TTP found\n")
            continue
        except UnicodeDecodeError:
            with open(file_path, 'r', encoding='latin-1') as file:
                article_text = file.read()
            print(f"Debug: Successfully read file with fallback encoding: {file_path}")  # Debug print


        found_data = find_data_ids(article_text, mitre_data)
        if found_data:
            for name, id_ in found_data.items():
                print(f"Debug: Found TTP: {name}, ID: {id_}")  # Debug print
                new_content.append(f"TTP: {name}, {id_}\n")
        else:
            print(f"Debug: No TTP found in {filename}")  # Debug print
            new_content.append("No TTP found\n")

# Write the updated content to the new file
with open(new_output_file_path, 'w', encoding='utf-8') as file:
    file.writelines(new_content)

# Read the new file content and filter out TTPs with a period in the ID
with open(new_output_file_path, 'r', encoding='utf-8') as file:
    lines = file.readlines()

filtered_content = [line for line in lines if not (line.startswith('TTP:') and '.' in line)]

# Write the filtered content back to the file
with open(new_output_file_path, 'w', encoding='utf-8') as file:
    file.writelines(filtered_content)

print("Processing complete.")  # Indicate completion