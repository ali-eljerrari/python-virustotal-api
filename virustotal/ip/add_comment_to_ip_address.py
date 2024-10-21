import requests as req
import json
import logging


def add_comment_to_ip_address(api_key: str, ip_address: str, comment: str) -> bool:
    """
    Adds a comment to an IP address on VirusTotal.

    Parameters:
        api_key (str): Your VirusTotal API key.
        ip_address (str): The IP address to add a comment to.
        comment (str): The comment text to add.

    Returns:
        bool: True if the operation is successful, False otherwise.
    """

    # Validate API key
    if not isinstance(api_key, str) or not api_key.strip():
        logging.error('Invalid API key provided.')
        print('Invalid API key provided.')
        return False


    # Validate comment
    if not isinstance(comment, str) or not comment.strip():
        logging.error('Comment must be a non-empty string.')
        print('Comment must be a non-empty string.')
        return False


    headers = {
        'Accept': 'application/json',
        'x-apikey': api_key
    }

    url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip_address}/comments'

    payload = {
        "data": {
            "type": "comment",
            "attributes": {
                "text": comment
            }
        }
    }

    try:
        response = req.post(url, json=payload, headers=headers, timeout=30)
        response.raise_for_status()

        logging.info(f'Comment added to IP address {ip_address} successfully.')
        print(f'Comment added to IP address {ip_address} successfully.')

        return True

    except req.exceptions.HTTPError as http_err:
        status_code = http_err.response.status_code
        if status_code == 404:
            logging.error(f'IP address {ip_address} not found.')
            print(f'Error: IP address {ip_address} not found.')
        elif status_code == 403:
            logging.error('Access forbidden. Check your API key and permissions.')
            print('Error: Access forbidden. Check your API key and permissions.')
        elif status_code == 400:
            logging.error('Bad request. Please check your input parameters.')
            print('Error: Bad request. Please check your input parameters.')
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

    return False
