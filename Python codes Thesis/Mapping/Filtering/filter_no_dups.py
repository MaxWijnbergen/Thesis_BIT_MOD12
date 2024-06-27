# This code filters out the duplications for every file

def filter_duplicates(input_filename, output_filename):
    """
    Reads the input file, removes duplicate CWEs for each article,
    and writes the result to the output file. Also removes 'No CWE found' lines.
    """
    with open(input_filename, 'r') as infile, open(output_filename, 'w') as outfile:
        current_article = ""
        seen_cwes = set()
        
        for line in infile:
            if line.startswith('CVEs found in'):
                if current_article:
                    # Write the collected article with unique CWEs
                    outfile.write(current_article)
                    for cwe in seen_cwes:
                        outfile.write(f"{cwe}\n")
                    outfile.write("\n")
                current_article = line
                seen_cwes = set()
            elif line.startswith('TTP:'):
                current_article += line
            elif line.startswith('CVE-'):
                parts = line.split(': ')
                if len(parts) > 1:
                    cwe = parts[1].strip()
                    if cwe != "No CWE found":
                        seen_cwes.add(f"{cwe}")
        
        # Write the last collected article with unique CWEs
        if current_article:
            outfile.write(current_article)
            for cwe in seen_cwes:
                outfile.write(f"{cwe}\n")
            outfile.write("\n")


if __name__ == "__main__":
    input_file = 'filtered_matched_cve_cwe_ttp.txt'
    output_file = 'filtered_matched_no_dups.txt'
    filter_duplicates(input_file, output_file)