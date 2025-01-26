# Python code to filter out the first two lines of a CSV log file and print.

import csv

def print_first_two_rows(file_path):
    with open(file_path, 'r') as file:
        reader = csv.reader(file)
        # Loop through the first two rows and print them
        for i, row in enumerate(reader):
            print(row)
            if i == 1:  # Stop after printing the first two rows
                break

# Call the function with your file
print_first_two_rows('logs.csv')
