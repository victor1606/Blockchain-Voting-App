#!/usr/bin/env python3

import warnings
warnings.filterwarnings("ignore", category=UserWarning, module="multiversx_sdk_network_providers")

import sys
import time
import hashlib
import base64
import json
from pathlib import Path
from multiversx_sdk import *
from multiversx_sdk_core import *
from multiversx_sdk_network_providers.errors import GenericError

###############################################################################
# Classes and Utilities
###############################################################################

class ProxyNetworkProviderWithStatus(ProxyNetworkProvider):
    def get_transaction(self, tx_hash: str) -> Transaction:
        return super().get_transaction(tx_hash, with_process_status=True)

def hash_personal_info(personal_info: str, salt: str = "unique_salt") -> str:
    data = personal_info + salt
    return hashlib.sha256(data.encode()).hexdigest()

def get_account_nonce(proxy_provider: ProxyNetworkProvider, address: Address) -> int:
    account_info = proxy_provider.get_account(address)
    return account_info.nonce

def extract_data_field(transaction_details) -> str:
    if 'smartContractResults' in transaction_details:
        for result in transaction_details['smartContractResults']:
            if 'data' in result:
                return result['data']
    return None

def extract_address_from_pem(pem_file_path: str) -> str:
    with open(pem_file_path, 'r') as pem_file:
        first_line = pem_file.readline().strip()
        if "BEGIN PRIVATE KEY for" in first_line:
            return first_line.split("for ")[1].replace("-----", "").strip()
        else:
            raise ValueError("Invalid PEM file format. Could not extract address.")

def extract_and_print_smart_contract_errors(response):
    try:
        logs = response.get("logs", {})
        events = logs.get("events", [])

        for event in events:
            identifier = event.get("identifier")
            if identifier == "internalVMErrors":
                # Extract the 'data' field containing base64 encoded errors
                encoded_data = event.get("data", "")
                
                # Decode the base64 data to get the error message
                decoded_data = base64.b64decode(encoded_data).decode('utf-8')
                
                print("[!] Smart Contract Response Details:\n")
                print(decoded_data)
                return  # Exit after printing the error

        print("[+] No internal VM errors found in the transaction response.")

    except Exception as e:
        print(f"[!] Failed to extract error details: {e}")

def decode_smart_contract_response(response):
    if response.startswith('@'):
        hex_data = response[1:]  # Remove the '@' character
        try:
            decoded_response = bytes.fromhex(hex_data).decode('utf-8').upper()  # Convert hex to string and uppercase
            return decoded_response
        except ValueError:
            return "[!] Failed to decode smart contract response."
    return response

###############################################################################
# Configuration
###############################################################################

DEVNET_PROXY_URL = "https://devnet-api.multiversx.com"
SC_ADDRESS = "erd1qqqqqqqqqqqqqpgq8y24lpxfwcfu46k3ntjtsfppzht3teuxd8ss0t6ty7"
GAS_LIMIT = 10_000_000
CANDIDATES = []
CANDIDATE_FILE_PATH = "candidates.json"

###############################################################################
# Core Functions
###############################################################################

def register_and_vote(pem_file_path: str, personal_info: str, candidate_code: str):
    try:
        tx_address = extract_address_from_pem(pem_file_path)
        print(f"[+] Using wallet address: {tx_address}")

        signer = UserSigner.from_pem_file(Path(pem_file_path))
        proxy_provider_with_status = ProxyNetworkProviderWithStatus(DEVNET_PROXY_URL)
        awaiter_with_status = TransactionAwaiter(fetcher=proxy_provider_with_status)

        # Hash the personal info (CNP)
        info_hash = hash_personal_info(personal_info)

        # Build data payload for smart contract call
        data = f"registerAndVote@{info_hash.encode('utf-8').hex()}@{candidate_code.encode('utf-8').hex()}"
        data_bytes = data.encode()

        sender_address = Address.from_bech32(tx_address)
        receiver_address = Address.from_bech32(SC_ADDRESS)
        sender_nonce = get_account_nonce(proxy_provider_with_status, sender_address)

        transaction = Transaction(
            nonce=sender_nonce,
            sender=sender_address.bech32(),
            receiver=receiver_address.bech32(),
            value=0,
            gas_limit=GAS_LIMIT,
            data=data_bytes,
            chain_id="D",
        )

        transaction_computer = TransactionComputer()
        transaction.signature = signer.sign(transaction_computer.compute_bytes_for_signing(transaction))

        tx_hash = proxy_provider_with_status.send_transaction(transaction)
        print(f"[+] Transaction sent. Tx Hash: {tx_hash}")

        # Wait for transaction confirmation
        print("[*] Waiting for transaction confirmation...")
        completed_tx = awaiter_with_status.await_completed(tx_hash)
        print("[+] Transaction confirmed on the blockchain.")

        extract_and_print_smart_contract_errors(completed_tx.raw_response)

        response = extract_data_field(completed_tx.raw_response)
        if response:
            decoded_response = decode_smart_contract_response(response)
            print(f"[+] Smart Contract Response: {decoded_response}")
            if decoded_response == "OK":
                print(f"\n[+] RESULT: Successfully cast vote to candidate - {candidate_code}")

        else:
            print("[!] No positive response from the smart contract.")

    except GenericError as e:
        print("[!] Error during transaction:", e)
    except ValueError as e:
        print(f"[!] {e}")

def get_election_info():
    try:
        proxy_provider = ProxyNetworkProvider(DEVNET_PROXY_URL)
        query_runner = QueryRunnerAdapter(proxy_provider)
        query_controller = SmartContractQueriesController(query_runner)

        response = query_controller.query(
            contract=SC_ADDRESS,
            function="getElectionInfo",  # Must match the smart contract exactly
            arguments=[]
        )

        if isinstance(response, list) and response:
            info_bytes = response[0]
            info_str = bytes.fromhex(info_bytes.hex()).decode('utf-8')
            print("[+] Election Info:\n" + info_str)

            lines = info_str.splitlines()
            for line in lines:
                if " - " in line:
                    _, name = line.split(" - ", 1)  # Split on " - " and get the name
                    CANDIDATES.append(name.strip())
            
            with open(CANDIDATE_FILE_PATH, "w") as file:
                json.dump(CANDIDATES, file)
            print(f"[+] Candidate list saved to '{CANDIDATE_FILE_PATH}'.")
        else:
            print("[!] No election info available.")

    except GenericError as e:
        print(f"[!] Failed to fetch election info: {e}")

def get_all_results():
    try:
        with open(CANDIDATE_FILE_PATH, "r") as file:
            CANDIDATES = json.load(file)
    except FileNotFoundError:
        print(f"[!] Candidate file '{CANDIDATE_FILE_PATH}' not found. Please run the info command first.")
    except json.JSONDecodeError:
        print(f"[!] Failed to decode the candidate list from '{CANDIDATE_FILE_PATH}'.")
    
    try:
        proxy_provider = ProxyNetworkProvider(DEVNET_PROXY_URL)
        query_runner = QueryRunnerAdapter(proxy_provider)
        query_controller = SmartContractQueriesController(query_runner)

        response = query_controller.query(
            contract=SC_ADDRESS,
            function="getAllResults",  # Must match the smart contract exactly
            arguments=[]
        )

        if isinstance(response, list) and response:
            print("Election results:")
            for i in range(0, len(response), 2):
                candidate_code = bytes.fromhex(response[i].hex()).decode('utf-8')
                vote_count = int.from_bytes(response[i + 1], byteorder='big')
                if len(CANDIDATES) > 0:
                    print(f"[+] Name: {CANDIDATES[i // 2]} - Candidate code: {candidate_code}: {vote_count} votes")
        else:
            print("[!] No voting results available.")

    except GenericError as e:
        print(f"[!] Failed to fetch voting results: {e}")

###############################################################################
# CLI Entry Point
###############################################################################

def main():
    if len(sys.argv) < 2:
        print("Usage:\n"
              "  python3 client.py vote <path_to_pem> <personal_info> <candidate_code>\n"
              "  python3 client.py info\n"
              "  python3 client.py results")
        sys.exit(1)

    command = sys.argv[1].lower()

    if command == "vote":
        if len(sys.argv) != 5:
            print("Usage: python3 client.py vote <path_to_pem> <personal_info> <candidate_code>")
            sys.exit(1)

        pem_file_path = sys.argv[2]
        personal_info = sys.argv[3]

        if len(personal_info) != 13:
            print("ERROR: CNP should have 13 digits!")
            sys.exit(1)

        candidate_code = sys.argv[4]
        if len(candidate_code) != 3:
            print("ERROR: Candidate code should have 3 digits!")
            sys.exit(1)

        register_and_vote(pem_file_path, personal_info, candidate_code)

    elif command == "info":
        get_election_info()

    elif command == "results":
        get_all_results()

    else:
        print("[!] Unknown command. Use 'vote', 'info', or 'results'.")

if __name__ == "__main__":
    main()
