import os
import sys
import requests as req
import json
import logging

def analyse_file_by_hash(api_key, hash_code):
    """
    Fetches the analysis of a file from VirusTotal using its hash code and saves the result to a JSON file.

    Parameters:
        api_key (str): Your VirusTotal API key.
        hash_code (str): The hash code of the file to analyze.

    Returns:
        None
    """

    # Validate API key
    if not api_key or not isinstance(api_key, str):
        logging.error('Invalid API key provided.')
        print('Invalid API key provided.')
        return

    # Validate hash code
    if not hash_code or not isinstance(hash_code, str):
        logging.error('Invalid hash code provided.')
        print('Invalid hash code provided.')
        return

    headers = {
        'accept': 'application/json',
        'x-apikey': api_key  # Corrected header key to lowercase 'x-apikey'
    }

    url = f'https://www.virustotal.com/api/v3/files/{hash_code}'

    try:
        response = req.get(url, headers=headers, timeout=30)
        response.raise_for_status()

        json_response = response.json()

        # Ensure 'files' directory exists
        files_dir = os.path.join(os.getcwd(), 'results', 'files')
        os.makedirs(files_dir, exist_ok=True)

        # Construct the file path
        file_name = f'{hash_code}.analysis_response.json'
        file_path = os.path.join(files_dir, file_name)

        # Write formatted JSON to the file
        with open(file_path, 'w', encoding='utf-8') as file:
            json.dump(json_response, file, indent=4, ensure_ascii=False)
        logging.info(f'Analysis for {hash_code} saved to {file_path}')
        print(f'Analysis for {hash_code} saved to {file_path}')
        sys.exit(1)

    except req.exceptions.HTTPError as http_err:
        status_code = http_err.response.status_code
        if status_code == 404:
            logging.error(f'File with hash {hash_code} not found.')
            print(f'Error: File with hash {hash_code} not found.')
        elif status_code == 403:
            logging.error('Access forbidden. Check your API key and permissions.')
            print('Error: Access forbidden. Check your API key and permissions.')
        else:
            logging.error(f'HTTP error occurred: {http_err}')
            print(f'HTTP error occurred: {http_err}')
    except req.exceptions.Timeout:
        logging.error('Request timed out.')
        print('Error: Request timed out.')
    except req.exceptions.RequestException as req_err:
        logging.error(f'Request exception occurred: {req_err}')
        print(f'Request exception occurred: {req_err}')
    except json.JSONDecodeError as json_err:
        logging.error(f'JSON decode error: {json_err}')
        print(f'Error decoding JSON response: {json_err}')
    except Exception as err:
        logging.error(f'An unexpected error occurred: {err}')
        print(f'An unexpected error occurred: {err}')
