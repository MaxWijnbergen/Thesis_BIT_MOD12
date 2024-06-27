import os
# This code is used to change the file types of the files in the CTI map, it was easier for me to change them to text files

# Path to the directory containing files
directory_path = 'C:\\Users\\Gebruiker\\Downloads\\cti'  # Adjust the path as needed

# List the contents of the directory
print(f"Debug: Listing contents of {directory_path}")
dir_contents = os.listdir(directory_path)
for item in dir_contents:
    print(f"Directory item: '{item}'")

# Rename all files to have .txt extension
for filename in dir_contents:
    if not filename.endswith('.txt'):
        base = os.path.splitext(filename)[0]  # Get the base name without extension
        new_filename = base + '.txt'  # Append .txt extension
        old_file_path = os.path.join(directory_path, filename)
        new_file_path = os.path.join(directory_path, new_filename)
        try:
            os.rename(old_file_path, new_file_path)
            print(f"Renamed '{old_file_path}' to '{new_file_path}'")
        except PermissionError as e:
            print(f"Could not rename '{old_file_path}'. Error: {e}")

# Confirm the renaming
print("Renaming complete. New directory contents:")
new_dir_contents = os.listdir(directory_path)
for item in new_dir_contents:
    print(f"New directory item: '{item}'")