# This code filters out all the text files that do not have a TTP or CWE, only text files with both TTPs and CWEs will be kept. 

def filter_sections_with_ttp_and_cwe(input_file, output_file):
    with open(input_file, 'r') as infile, open(output_file, 'w') as outfile:
        current_section = []
        has_ttp = False
        has_cwe = False

        for line in infile:
            if line.strip() == "":
                if has_ttp and has_cwe:
                    outfile.writelines(current_section)
                    outfile.write("\n")
                current_section = []
                has_ttp = False
                has_cwe = False
            else:
                current_section.append(line)
                if "TTP:" in line:
                    has_ttp = True
                if "CWE-" in line:
                    has_cwe = True

        # Check the last section if the file doesn't end with a blank line
        if has_ttp and has_cwe:
            outfile.writelines(current_section)

input_file = r'C:\Users\Gebruiker\Downloads\cti\matched_cve_cwe_ttp.txt'
output_file = 'filtered_matched_cve_cwe_ttp.txt'
filter_sections_with_ttp_and_cwe(input_file, output_file)