import boto3
import pandas as pd
from resourcequery import *
from botocore.errorfactory import ClientError

# Load the CSV file
try:
    df = pd.read_csv('./resources.csv', header=None)
except Exception as e:
    print(f"Error reading the CSV file: {e}")
    exit()

session = boto3.session.Session()
regions = ['us-east-1','eu-west-1']

# # Loop through each function name in the DataFrame
# for function_name in df[0]:
#     try:
#         # Print the function name for debugging purposes
#         print(f"Processing function: {function_name}")

#         # Call the function by name
#         func = globals()[function_name]
#         total_sum += func(session, regions)
#     except KeyError:
#         print(f"Function '{function_name}' not found in the global namespace.")
#     except Exception as e:
#         print(f"Error executing function '{function_name}': {e}")

# print(f"Total sum of responses: {total_sum}")

# Initialize a list to hold the results
results = []

# Loop through each function name in the DataFrame
for function_name in df[0]:
    try:
        # Print the function name for debugging purposes
        print(f"Processing function: {function_name}")

        # Get the function from the map and call it with session and regions as parameters
        func = globals()[function_name]
        count = func(session, regions)
        
        # Append the result to the results list
        results.append({'function_name': function_name, 'asset_count': count})
        
    except KeyError as ke:
        # print(f"Function '{function_name}' not found in the function map.")
        print(f"{ke.args}")
    except Exception as e:
        print(f"Error executing function '{function_name}': {e}")

# Create a DataFrame from the results list
results_df = pd.DataFrame(results)

# Save the results to a CSV file
output_file_path = './function_counts.csv'
results_df.to_csv(output_file_path, index=False)

print(f"Results saved to {output_file_path}")