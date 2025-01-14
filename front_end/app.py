from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
import json
import os
from pathlib import Path
from multiversx_sdk import *
from multiversx_sdk_core import *
from multiversx_sdk_network_providers.errors import GenericError
import base64
import hashlib
import re
from PIL import Image
import pytesseract

app = Flask(__name__)
app.secret_key = "your_secret_key"

# Configuration
DEVNET_PROXY_URL = "https://devnet-api.multiversx.com"
SC_ADDRESS = "erd1qqqqqqqqqqqqqpgq8y24lpxfwcfu46k3ntjtsfppzht3teuxd8ss0t6ty7"
GAS_LIMIT = 10_000_000
CANDIDATE_FILE_PATH = "candidates.json"
UPLOAD_FOLDER = "user_wallets"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
pytesseract.pytesseract.tesseract_cmd = "/usr/bin/tesseract"

class ProxyNetworkProviderWithStatus(ProxyNetworkProvider):
    def get_transaction(self, tx_hash: str) -> Transaction:
        return super().get_transaction(tx_hash, with_process_status=True)

# Utilities
def extract_address_from_pem(pem_file_path: str) -> str:
    with open(pem_file_path, "r") as pem_file:
        first_line = pem_file.readline().strip()
        if "BEGIN PRIVATE KEY for" in first_line:
            return first_line.split("for ")[1].replace("-----", "").strip()
        else:
            raise ValueError("Invalid PEM file format. Could not extract address.")

def hash_personal_info(personal_info: str, salt: str = "unique_salt") -> str:
    data = personal_info + salt
    return hashlib.sha256(data.encode()).hexdigest()

# def extract_and_log_smart_contract_errors(response):
#     try:
#         logs = response.get("logs", {})
#         events = logs.get("events", [])
#
#         for event in events:
#             identifier = event.get("identifier")
#             if identifier == "internalVMErrors":
#                 encoded_data = event.get("data", "")
#                 decoded_data = base64.b64decode(encoded_data).decode("utf-8")
#
#                 # Remove technical details: runtime.go references, [registerAndVote], etc.
#                 cleaned_message = re.sub(r'runtime\.go:\d+\s*\[.*?\]\s*', '', decoded_data)
#                 cleaned_message = re.sub(r'\[.*?\]', '', cleaned_message).strip()
#
#                 # Extract the most meaningful part of the error (e.g., the last sentence)
#                 user_friendly_message = cleaned_message.splitlines()[-1].strip()
#
#                 return user_friendly_message  # Return clean, user-friendly message
#
#         return None  # No errors found
#
#     except Exception as e:
#         return f"Failed to extract error details: {e}"

def extract_and_log_smart_contract_errors(response):
    try:
        logs = response.get("logs", {})
        events = logs.get("events", [])

        if not events:
            return None

        for event in events:
            identifier = event.get("identifier")
            if identifier == "internalVMErrors":
                encoded_data = event.get("data", "")

                if not encoded_data:
                    return "Smart contract error occurred, but no details were provided."

                decoded_data = base64.b64decode(encoded_data).decode("utf-8")
                to_remove = ["runtime.go:853","runtime.go:856", "[registerAndVote]", "[error signalled by smartcontract]", "[", "]", "Url = [https://devnet-api.multiversx.com/transaction/send], error = {'data': None, 'error': 'transaction generation failed: ", ", 'code': 'internal_issue'}"]

                for substring in to_remove:
                    decoded_data = decoded_data.replace(substring, "")

                return decoded_data.strip()
        return None  # No internal VM errors found

    except (IndexError, KeyError, ValueError, TypeError) as e:
        # Handle cases where unexpected data structures are encountered
        return f"Failed to extract smart contract error details: {str(e)}"


def decode_smart_contract_response(response):
    if response.startswith("@"):
        hex_data = response[1:]  # Remove the '@' character
        try:
            decoded_response = bytes.fromhex(hex_data).decode("utf-8").upper()  # Convert hex to string and uppercase
            return decoded_response
        except ValueError:
            return "[!] Failed to decode smart contract response."
    return response

def extract_data_field(transaction_details) -> str:
    if 'smartContractResults' in transaction_details:
        for result in transaction_details['smartContractResults']:
            if 'data' in result:
                return result['data']
    return None

def get_account_nonce(proxy_provider: ProxyNetworkProvider, address: Address) -> int:
    account_info = proxy_provider.get_account(address)
    return account_info.nonce

@app.route("/")
def index():
    return render_template("base.html")

@app.route("/vote", methods=["POST"])
def vote():
    logs = []

    pem_file = request.files.get("pem_file")
    entered_cnp = request.form.get("personal_info")
    candidate_code = request.form.get("candidate_code")
    id_card_photo = request.files.get("id_card_photo")
    print(id_card_photo.filename.endswith(".jpg"))

    if not pem_file or not pem_file.filename.endswith(".pem"):
        logs.append("[!] Please upload a valid .pem file!")
        return jsonify({"status": "error", "logs": logs}), 400

    if not id_card_photo.filename.endswith(".jpg"):
        logs.append("[!] Please upload a valid image!")
        return jsonify({"status": "error", "logs": logs}), 400

    print(logs)

    try:
        # Process the ID card photo
        id_card_image = Image.open(id_card_photo)
        extracted_text = pytesseract.image_to_string(id_card_image, lang="eng")

        # Extract CNP from the text
        cnp_match = re.search(r'\b\d{13}\b', extracted_text)
        if not cnp_match:
            print("Could not extract CNP from the uploaded image.")
            logs.append("[!] Could not extract CNP from the uploaded image.")
            return jsonify({"status": "error", "logs": logs}), 400

        extracted_cnp = cnp_match.group(0)
        print(f"[+] Extracted CNP: {extracted_cnp}")

        # Compare the extracted CNP with the entered CNP
        # if entered_cnp != extracted_cnp:
        #     print("The entered CNP does not match the CNP extracted from the ID card.")
        #     logs.append("[!] The entered CNP does not match the CNP extracted from the ID card.")
        #     return jsonify({"status": "error", "logs": logs}), 400

        # Save the PEM file
        pem_path = os.path.join(UPLOAD_FOLDER, pem_file.filename)
        pem_file.save(pem_path)

        # Extract wallet address and signer
        tx_address = extract_address_from_pem(pem_path)
        logs.append(f"[+] Extracted wallet address: {tx_address}")
        signer = UserSigner.from_pem_file(Path(pem_path))

        # Initialize Proxy and Transaction Awaiter
        proxy_provider = ProxyNetworkProviderWithStatus(DEVNET_PROXY_URL)
        awaiter_with_status = TransactionAwaiter(fetcher=proxy_provider)

        # Get sender nonce
        sender_nonce = proxy_provider.get_account(Address.from_bech32(tx_address)).nonce

        # Prepare transaction data
        info_hash = hash_personal_info(entered_cnp)  # Use the entered CNP
        data = f"registerAndVote@{info_hash.encode('utf-8').hex()}@{candidate_code.encode('utf-8').hex()}"

        # Create and sign transaction
        transaction = Transaction(
            nonce=sender_nonce,
            sender=tx_address,
            receiver=SC_ADDRESS,
            value=0,
            gas_limit=GAS_LIMIT,
            data=data.encode(),
            chain_id="D"
        )
        transaction_computer = TransactionComputer()
        transaction.signature = signer.sign(transaction_computer.compute_bytes_for_signing(transaction))

        # Send transaction
        tx_hash = proxy_provider.send_transaction(transaction)
        logs.append(f"[+] Transaction sent. Tx Hash: {tx_hash}")
        print(f"[+] Transaction sent. Tx Hash: {tx_hash}")

        # Wait for confirmation
        completed_tx = awaiter_with_status.await_completed(tx_hash)
        logs.append("[+] Transaction confirmed on the blockchain.")
        print("[+] Transaction confirmed on the blockchain.")

        # Check for smart contract response and errors
        raw_response = completed_tx.raw_response
        error_message = extract_and_log_smart_contract_errors(raw_response)
        if error_message:
            logs.append(f"[!] Smart Contract Error: {error_message}")
            print(f"[!] Smart Contract Error: {error_message}")

        # Decode smart contract response
        response = extract_data_field(raw_response)
        decoded_response = decode_smart_contract_response(response) if response else "No response"
        # logs.append(f"[+] Smart Contract Response: {decoded_response}")

        return jsonify({
            "status": "success",
            "transaction_hash": tx_hash,
            "logs": logs
        }), 200

    except Exception as e:
        error_log = f"[!] Error during voting: {e}"
        logs.append(error_log)
        return jsonify({"status": "error", "logs": logs}), 500

@app.route("/info")
def election_info():
    try:
        proxy_provider = ProxyNetworkProvider(DEVNET_PROXY_URL)
        query_runner = QueryRunnerAdapter(proxy_provider)
        query_controller = SmartContractQueriesController(query_runner)

        response = query_controller.query(contract=SC_ADDRESS, function="getElectionInfo", arguments=[])
        if isinstance(response, list) and response:
            info_bytes = response[0]
            info_str = bytes.fromhex(info_bytes.hex()).decode("utf-8")
            return jsonify({"status": "success", "info": info_str}), 200
        return jsonify({"status": "error", "message": "No election info available."}), 404

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route("/results")
def results():
    try:
        proxy_provider = ProxyNetworkProvider(DEVNET_PROXY_URL)
        query_runner = QueryRunnerAdapter(proxy_provider)
        query_controller = SmartContractQueriesController(query_runner)

        response = query_controller.query(contract=SC_ADDRESS, function="getAllResults", arguments=[])
        results = []
        if isinstance(response, list) and response:
            for i in range(0, len(response), 2):
                candidate_code = bytes.fromhex(response[i].hex()).decode("utf-8")
                vote_count = int.from_bytes(response[i + 1], byteorder="big")
                results.append({"code": candidate_code, "votes": vote_count})
            return jsonify({"status": "success", "results": results}), 200
        return jsonify({"status": "error", "message": "No results available."}), 404

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


if __name__ == "__main__":
    app.run(debug=True)
