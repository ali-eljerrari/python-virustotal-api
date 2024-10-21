import os
import sys
import requests as req
import json
import logging

def get_comments_ip_address(api_key: str, ip_address: str, limit: int = 10) -> bool:
    """
    Retrieves comments for an IP address from VirusTotal and saves the result to a JSON file.

    Parameters:
        api_key (str): Your VirusTotal API key.
        ip_address (str): The IP address to retrieve comments for.
        limit (int): Number of comments to retrieve (default is 10, max is 100).

    Returns:
        bool: True if the operation is successful, False otherwise.
    """

    # Validate API key
    if not isinstance(api_key, str) or not api_key.strip():
        logging.error('Invalid API key provided.')
        print('Invalid API key provided.')
        return False


    # Validate limit
    if not isinstance(limit, int) or limit < 1 or limit > 100:
        logging.error('Limit must be an integer between 1 and 100.')
        print('Limit must be an integer between 1 and 100.')
        return False


    headers = {
        'accept': 'application/json',
        'x-apikey': api_key
    }

    url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip_address}/comments?limit={limit}'

    try:
        response = req.get(url, headers=headers, timeout=30)
        response.raise_for_status()

        json_response = response.json()

        # Check if there are comments
        if not json_response.get('data'):
            print(f"No comments found for IP address {ip_address}.")
            logging.info(f"No comments found for IP address {ip_address}.")
            return True

        # Ensure 'results/ip_addresses/comments' directory exists
        results_dir = os.path.join(os.getcwd(), 'results', 'ip_addresses', 'comments')
        os.makedirs(results_dir, exist_ok=True)

        # Sanitize filename (replace ':' in IPv6 addresses)
        sanitized_ip = ip_address.replace(':', '_')

        # Construct the file path
        file_name = f'{sanitized_ip}.comments.json'
        file_path = os.path.join(results_dir, file_name)

        # Write formatted JSON to the file
        with open(file_path, 'w', encoding='utf-8') as file:
            json.dump(json_response, file, indent=4, ensure_ascii=False)

        logging.info(f'Comments for IP address {ip_address} saved to {file_path}')
        print(f'Comments for IP address {ip_address} saved to {file_path}')

        sys.exit(1)
        # return True

    except req.exceptions.HTTPError as http_err:
        status_code = http_err.response.status_code
        if status_code == 404:
            logging.error(f'IP address {ip_address} not found.')
            print(f'Error: IP address {ip_address} not found.')
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
    except IOError as io_err:
        logging.error(f'File I/O error: {io_err}')
        print(f'File I/O error: {io_err}')
    except Exception as err:
        logging.error(f'An unexpected error occurred: {err}')
        print(f'An unexpected error occurred: {err}')

    return False
