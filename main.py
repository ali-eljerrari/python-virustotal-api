import os
import sys
import logging
import ipaddress
from dotenv import load_dotenv

from virustotal.files.analyse_file_by_hash import analyse_file_by_hash
from virustotal.files.check_analysis_result import check_analysis_result
from virustotal.files.submit_file_for_analysis import submit_file_for_analysis
from virustotal.ip.check_ip_address import check_ip_address
from virustotal.ip.get_comments_ip_address import get_comments_ip_address
from virustotal.ip.rescan_ip_address import rescan_ip_address


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
        format='%(asctime)s %(levelname)s:%(message)s'
    )

    while True:
        print('\nPlease select an option:')
        print('\nFor analysing IP addresses:')
        print('1. Get an IP address report')
        print('2. Request an IP address rescan (re-analyze)s')
        print('3. Get comments on an IP address')
        print('4. Add a comment to an IP address')
        print('5. Get objects related to an IP address')
        print('6. Get object descriptors related to an IP address')
        print('7. Get votes on an IP address')
        print('8. Add a vote to an IP address')
        print('\nFor analysing files:')
        print('9. Analyze a file by hash')
        print('10. Submit a file for analysis')
        print('11. Analyze a file by analysis id')
        print('0. Exit')

        choice = input('Enter your choice: ').strip()

        if choice == '1':
            ip_address = input('Please provide IP address: ').strip()
            if not ip_address:
                print('Invalid IP address provided!')
                continue
            check_ip_address(api_key, ip_address)

        elif choice == '2':
            ip_address = input('Please provide IP address: ').strip()
            if not ip_address:
                print('Invalid IP address provided!')
                continue
            rescan_ip_address(api_key, ip_address)


        elif choice == '3':
            ip_address = input('Please provide IP address: ').strip()

            # Validate the IP address
            try:
                ipaddress.ip_address(ip_address)

            except ValueError:
                print('Invalid IP address provided!')
                continue

            limit = input('Number of comments to get: ')

            # Convert limit to integer and validate
            try:
                limit = int(limit)

                if limit < 1 or limit > 100:
                    print('Number of comments should be between 1 and 100')
                    continue

            except ValueError:
                print('Invalid Number of comments provided')
                continue

            # Call the function with validated inputs
            get_comments_ip_address(api_key, ip_address, limit)

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
                print('Invalid ID provided!')
                continue
            check_analysis_result(api_key, analysis_id)

        elif choice == '0':
            print('Exiting the program.')
            sys.exit(0)

        else:
            print('Invalid choice. Try again!')

if __name__ == '__main__':
    main()
