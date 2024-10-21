import os
import sys
import time
import logging
import requests as req
import json

def check_analysis_result(api_key, analysis_id):
    """
    Checks the analysis result of a submitted file on VirusTotal using the analysis ID.

    Parameters:
        api_key (str): Your VirusTotal API key.
        analysis_id (str): The analysis ID obtained after submitting a file.

    Returns:
        bool: True if the analysis is completed and the result is saved successfully, False otherwise.
    """

    # Validate API key
    if not api_key or not isinstance(api_key, str):
        logging.error('Invalid API key provided.')
        print('Invalid API key provided.')
        return False

    # Validate analysis ID
    if not analysis_id or not isinstance(analysis_id, str):
        logging.error('Invalid analysis ID provided.')
        print('Invalid analysis ID provided.')
        return False

    headers = {
        'accept': 'application/json',
        'x-apikey': api_key  # Corrected header key to lowercase 'x-apikey'
    }

    url = f'https://www.virustotal.com/api/v3/analyses/{analysis_id}'

    print('Checking analysis status...')

    max_retries = 20  # Maximum number of retries
    retry_count = 0
    retry_delay = 15  # Delay in seconds between retries

    try:
        while retry_count < max_retries:
            try:
                response = req.get(url, headers=headers, timeout=30)
                response.raise_for_status()

                json_response = response.json()

                analysis_status = json_response['data']['attributes']['status']

                if analysis_status == 'completed':
                    print('Analysis completed.')
                    logging.info(f'Analysis {analysis_id} completed.')

                    # Ensure 'files' directory exists
                    files_dir = os.path.join(os.getcwd(), 'files')
                    os.makedirs(files_dir, exist_ok=True)

                    # Construct the file path using os.path.join
                    file_name = f'{analysis_id}.analysis_result.json'
                    analysis_file_path = os.path.join(files_dir, file_name)

                    # Write formatted JSON to the file
                    with open(analysis_file_path, 'w', encoding='utf-8') as result_file:
                        json.dump(json_response, result_file, indent=4, ensure_ascii=False)
                    print(f'Analysis result saved to {analysis_file_path}')
                    sys.exit(1)
                    # return True
                elif analysis_status == 'error':
                    print('Analysis resulted in an error.')
                    logging.error(f'Analysis {analysis_id} resulted in an error.')
                    return False
                else:
                    print(f'Analysis status: {analysis_status}. Waiting for completion... ({retry_count + 1}/{max_retries})')
                    retry_count += 1
                    time.sleep(retry_delay)  # Wait before checking again

            except req.exceptions.HTTPError as http_err:
                status_code = http_err.response.status_code
                if status_code == 403:
                    logging.error('Access forbidden. Check your API key and permissions.')
                    print('Error: Access forbidden. Check your API key and permissions.')
                elif status_code == 429:
                    logging.error('Rate limit exceeded.')
                    print('Error: Rate limit exceeded. Please try again later.')
                elif status_code == 404:
                    logging.error(f'Analysis ID {analysis_id} not found.')
                    print(f'Error: Analysis ID {analysis_id} not found.')
                else:
                    logging.error(f'HTTP error occurred while checking analysis result: {http_err}')
                    print(f'HTTP error occurred while checking analysis result: {http_err}')
                return False
            except req.exceptions.Timeout:
                logging.error('Request timed out.')
                print('Error: Request timed out.')
                return False
            except req.exceptions.RequestException as req_err:
                logging.error(f'Request exception occurred: {req_err}')
                print(f'Request exception occurred: {req_err}')
                return False
            except json.JSONDecodeError as json_err:
                logging.error(f'JSON decode error: {json_err}')
                print(f'Error decoding JSON response: {json_err}')
                return False
            except Exception as err:
                logging.error(f'An unexpected error occurred while checking analysis result: {err}')
                print(f'An unexpected error occurred while checking analysis result: {err}')
                return False
        else:
            print('Maximum retries reached. The analysis may still be processing. Please check later.')
            logging.info(f'Maximum retries reached for analysis {analysis_id}.')
            return False

    except KeyboardInterrupt:
        print('\nProcess interrupted by user. Exiting...')
        logging.info('Process interrupted by user during analysis checking.')
        return False
