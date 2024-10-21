import os
import sys
import logging
from dotenv import load_dotenv

from virustotal.analyse_file_by_hash import analyse_file_by_hash

from virustotal.check_analysis_result import check_analysis_result

from virustotal.submit_file_for_analysis import submit_file_for_analysis


def main():
    # Load environment variables
    load_dotenv()

    # Get the API key from environment variables
    api_key = os.environ.get("API_KEY")

    if not api_key:
        print("API_KEY not found in environment variables.")
        sys.exit(1)

    # Configure logging
    logging.basicConfig(
        filename='fetch_api.log',
        level=logging.INFO,
        format='%(asctime)s %(levelname)s:%(message)s'
    )

    while True:
        print("\nPlease select an option:")
        print("1. Analyze a file by hash")
        print("2. Submit a file for analysis")
        print("3. Analyze a file by analysis id")
        print("4. Exit")

        choice = input("Enter your choice (1, 2, 3, or 4): ").strip()

        if choice == '1':
            hash_code = input("Please provide the hash of the file: ").strip()
            if not hash_code:
                print("Hash code of the file was not provided!")
                continue
            analyse_file_by_hash(api_key, hash_code)

        elif choice == '2':
            file_path = input("Please provide the path to the file: ").strip()
            if not file_path or not os.path.isfile(file_path):
                print("Invalid file path provided!")
                continue
            submit_file_for_analysis(api_key, file_path)

        elif choice == '3':
            analysis_id = input("Please provide the analysis ID: ").strip()
            if not analysis_id:
                print("Invalid file path provided!")
                continue
            check_analysis_result(api_key, analysis_id)

        elif choice == '4':
            print("Exiting the program.")
            sys.exit(0)

        else:
            print("Invalid choice. Please enter 1, 2, 3, or 4.")

if __name__ == '__main__':
    main()
