import requests as req
import json
import logging
import ipaddress

def rescan_ip_address(api_key, ip_address):
    """
    Submits an IP address to VirusTotal for reanalysis and returns the analysis ID.

    Parameters:
        api_key (str): Your VirusTotal API key.
        ip_address (str): The IP address to rescan.

    Returns:
        str: The analysis ID if submission is successful, None otherwise.
    """

    # Validate API key
    if not api_key or not isinstance(api_key, str):
        logging.error('Invalid API key provided.')
        print('Invalid API key provided.')
        return None

    # Validate IP address
    if not ip_address or not isinstance(ip_address, str):
        logging.error('Invalid IP address provided.')
        print('Invalid IP address provided.')
        return None

    # Check if IP address is valid
    try:
        ipaddress.ip_address(ip_address)
    except ValueError:
        logging.error(f'Invalid IP address format: {ip_address}')
        print(f'Invalid IP address format: {ip_address}')
        return None

    headers = {
        'accept': 'application/json',
        'x-apikey': api_key
    }

    url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip_address}/analyse'

    try:
        response = req.post(url, headers=headers, timeout=30)
        response.raise_for_status()

        json_response = response.json()

        # Get the analysis ID from the response
        analysis_id = json_response.get('data', {}).get('id')

        if analysis_id:
            print(f'IP address submitted for reanalysis successfully. Analysis ID: {analysis_id}')
            logging.info(f'IP address {ip_address} submitted for reanalysis successfully. Analysis ID: {analysis_id}')
            return analysis_id
        else:
            logging.error('Failed to retrieve analysis ID from response.')
            print('Error: Failed to retrieve analysis ID from response.')
            return None

    except req.exceptions.HTTPError as http_err:
        status_code = http_err.response.status_code
        if status_code == 404:
            logging.error(f'IP address {ip_address} not found.')
            print(f'Error: IP address {ip_address} not found.')
        elif status_code == 403:
            logging.error('Access forbidden. Check your API key and permissions.')
            print('Error: Access forbidden. Check your API key and permissions.')
        elif status_code == 429:
            logging.error('Rate limit exceeded.')
            print('Error: Rate limit exceeded. Please try again later.')
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

    return None
