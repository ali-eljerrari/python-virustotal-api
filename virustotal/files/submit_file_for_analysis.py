import requests as req
import os
import json
import logging

def submit_file_for_analysis(api_key, file_path):
    """
    Submits a file to VirusTotal for analysis and returns the analysis ID.

    Parameters:
        api_key (str): Your VirusTotal API key.
        file_path (str): The path to the file to submit for analysis.

    Returns:
        str: The analysis ID if submission is successful, None otherwise.
    """

    # Validate API key
    if not api_key or not isinstance(api_key, str):
        logging.error('Invalid API key provided.')
        print('Invalid API key provided.')
        return None

    # Validate file path
    if not file_path or not isinstance(file_path, str):
        logging.error('Invalid file path provided.')
        print('Invalid file path provided.')
        return None

    if not os.path.isfile(file_path):
        logging.error(f'File does not exist: {file_path}')
        print(f'File does not exist: {file_path}')
        return None

    headers = {
        'accept': 'application/json',
        'x-apikey': api_key  # Corrected header key to lowercase 'x-apikey'
    }

    url = 'https://www.virustotal.com/api/v3/files'

    try:
        with open(file_path, 'rb') as file_to_submit:
            files = {'file': (os.path.basename(file_path), file_to_submit)}
            response = req.post(url, headers=headers, files=files, timeout=60)
            response.raise_for_status()

            json_response = response.json()

            # Get the analysis ID from the response
            analysis_id = json_response.get('data', {}).get('id')

            if analysis_id:
                print(f'File submitted successfully. Analysis ID: {analysis_id}')
                logging.info(f'File {file_path} submitted successfully. Analysis ID: {analysis_id}')
                return analysis_id
            else:
                logging.error('Failed to retrieve analysis ID from response.')
                print('Error: Failed to retrieve analysis ID from response.')
                return None

    except req.exceptions.HTTPError as http_err:
        status_code = http_err.response.status_code
        if status_code == 403:
            logging.error('Access forbidden. Check your API key and permissions.')
            print('Error: Access forbidden. Check your API key and permissions.')
        elif status_code == 429:
            logging.error('Rate limit exceeded.')
            print('Error: Rate limit exceeded. Please try again later.')
        else:
            logging.error(f'HTTP error occurred during file submission: {http_err}')
            print(f'HTTP error occurred during file submission: {http_err}')
    except req.exceptions.Timeout:
        logging.error('Request timed out.')
        print('Error: Request timed out.')
    except req.exceptions.RequestException as req_err:
        logging.error(f'Request exception occurred: {req_err}')
        print(f'Request exception occurred: {req_err}')
    except FileNotFoundError:
        logging.error(f'File not found: {file_path}')
        print(f'Error: File not found: {file_path}')
    except json.JSONDecodeError as json_err:
        logging.error(f'JSON decode error: {json_err}')
        print(f'Error decoding JSON response: {json_err}')
    except Exception as err:
        logging.error(f'An unexpected error occurred during file submission: {err}')
        print(f'An unexpected error occurred during file submission: {err}')

    return None
