import os
import sys
import logging
import ipaddress
from dotenv import load_dotenv

from virustotal.files.analyse_file_by_hash import analyse_file_by_hash
from virustotal.files.check_analysis_result import check_analysis_result
from virustotal.files.submit_file_for_analysis import submit_file_for_analysis
from virustotal.ip.check_ip_address import check_ip_address
from virustotal.ip.add_comment_to_ip_address import add_comment_to_ip_address
from virustotal.ip.get_comments_ip_address import get_comments_ip_address
from virustotal.ip.rescan_ip_address import rescan_ip_address


def get_valid_ip(prompt='Please provide an IP address: '):
    """Prompt the user for a valid IP address."""
    while True:
        ip_address = input(prompt).strip()
        if not ip_address:
            print('IP address cannot be empty!')
            continue
        try:
            ipaddress.ip_address(ip_address)
            return ip_address
        except ValueError:
            print('Invalid IP address format! Please try again.')


def get_valid_int(prompt, min_value=None, max_value=None):
    """Prompt the user for a valid integer within a specified range."""
    while True:
        value = input(prompt).strip()
        try:
            value = int(value)
            if (min_value is not None and value < min_value) or \
               (max_value is not None and value > max_value):
                print(f'Please enter a number between {min_value} and {max_value}.')
                continue
            return value
        except ValueError:
            print('Please enter a valid integer.')


def main():
    # Load environment variables
    load_dotenv()

    # Get the API key from environment variables
    api_key = os.environ.get('API_KEY')

    if not api_key:
        print('API_KEY not found in environment variables.')
        sys.exit(1)

    # Configure logging
    logging.basicConfig(
        filename='fetch_api.log',
        level=logging.INFO,
        format='%(asctime)s %(levelname)s: %(message)s'
    )

    menu_options = {
        '1': 'Get an IP address report',
        '2': 'Request an IP address rescan (re-analyze)',
        '3': 'Get comments on an IP address',
        '4': 'Add a comment to an IP address',
        '5': 'Get objects related to an IP address',
        '6': 'Get object descriptors related to an IP address',
        '7': 'Get votes on an IP address',
        '8': 'Add a vote to an IP address',
        '9': 'Get a file report',
        '10': 'Upload a file',
        '11': 'Get a URL / file analysis',
        '0': 'Exit'
    }

    while True:
        print('\nPlease select an option:')
        print('\nFor analyzing IP addresses:')
        for option in ['1', '2', '3', '4', '5', '6', '7', '8']:
            print(f'{option}. {menu_options[option]}')
        print('\nFor analyzing files:')
        for option in ['9', '10', '11']:
            print(f'{option}. {menu_options[option]}')
        print('\n0. Exit')

        choice = input('\nEnter your choice: ').strip()

        try:
            if choice == '1':
                ip_address = get_valid_ip()
                check_ip_address(api_key, ip_address)

            elif choice == '2':
                ip_address = get_valid_ip()
                rescan_ip_address(api_key, ip_address)

            elif choice == '3':
                ip_address = get_valid_ip()
                limit = get_valid_int('Number of comments to get (1-100): ', 1, 100)
                get_comments_ip_address(api_key, ip_address, limit)

            elif choice == '4':
                ip_address = get_valid_ip()
                comment = input('Insert your comment: ').strip()
                if not comment:
                    print('Comment cannot be empty!')
                    continue
                add_comment_to_ip_address(api_key, ip_address, comment)

            elif choice == '9':
                hash_code = input('Please provide the hash of the file: ').strip()
                if not hash_code:
                    print('Hash code of the file was not provided!')
                    continue
                analyse_file_by_hash(api_key, hash_code)

            elif choice == '10':
                file_path = input('Please provide the path to the file: ').strip()
                if not file_path or not os.path.isfile(file_path):
                    print('Invalid file path provided!')
                    continue
                submit_file_for_analysis(api_key, file_path)

            elif choice == '11':
                analysis_id = input('Please provide the analysis ID: ').strip()
                if not analysis_id:
                    print('Analysis ID cannot be empty!')
                    continue
                check_analysis_result(api_key, analysis_id)

            elif choice == '0':
                print('Exiting the program.')
                sys.exit(0)

            else:
                print('Invalid choice. Please try again.')

        except Exception as e:
            logging.error(f'An error occurred: {e}')
            print(f'An error occurred: {e}')

if __name__ == '__main__':
    main()
