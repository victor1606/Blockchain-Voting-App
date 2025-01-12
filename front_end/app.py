from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
import json
import os
from pathlib import Path
from multiversx_sdk import *
from multiversx_sdk_core import *
from multiversx_sdk_network_providers.errors import GenericError

app = Flask(__name__)
app.secret_key = "your_secret_key"

# Configuration
DEVNET_PROXY_URL = "https://devnet-api.multiversx.com"
SC_ADDRESS = "erd1qqqqqqqqqqqqqpgq8y24lpxfwcfu46k3ntjtsfppzht3teuxd8ss0t6ty7"
GAS_LIMIT = 10_000_000
CANDIDATE_FILE_PATH = "candidates.json"


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


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/info")
def election_info():
    try:
        proxy_provider = ProxyNetworkProvider(DEVNET_PROXY_URL)
        query_runner = QueryRunnerAdapter(proxy_provider)
        query_controller = SmartContractQueriesController(query_runner)

        response = query_controller.query(
            contract=SC_ADDRESS,
            function="getElectionInfo",
            arguments=[]
        )

        if isinstance(response, list) and response:
            info_bytes = response[0]
            info_str = bytes.fromhex(info_bytes.hex()).decode("utf-8")
            candidates = []

            lines = info_str.splitlines()
            for line in lines:
                if " - " in line:
                    _, name = line.split(" - ", 1)
                    candidates.append(name.strip())

            with open(CANDIDATE_FILE_PATH, "w") as file:
                json.dump(candidates, file)

            return render_template("election_info.html", info=info_str, candidates=candidates)

        flash("No election info available.")
        return redirect(url_for("index"))
    except Exception as e:
        flash(f"Error fetching election info: {e}")
        return redirect(url_for("index"))


@app.route("/results")
def results():
    try:
        with open(CANDIDATE_FILE_PATH, "r") as file:
            candidates = json.load(file)
    except FileNotFoundError:
        flash("Candidate file not found. Please fetch election info first.")
        return redirect(url_for("index"))
    except json.JSONDecodeError:
        flash("Failed to decode the candidate file.")
        return redirect(url_for("index"))

    try:
        proxy_provider = ProxyNetworkProvider(DEVNET_PROXY_URL)
        query_runner = QueryRunnerAdapter(proxy_provider)
        query_controller = SmartContractQueriesController(query_runner)

        response = query_controller.query(
            contract=SC_ADDRESS,
            function="getAllResults",
            arguments=[]
        )

        results = []
        if isinstance(response, list) and response:
            for i in range(0, len(response), 2):
                candidate_code = bytes.fromhex(response[i].hex()).decode("utf-8")
                vote_count = int.from_bytes(response[i + 1], byteorder="big")
                results.append({"code": candidate_code, "name": candidates[i // 2], "votes": vote_count})

        return render_template("results.html", results=results)
    except Exception as e:
        flash(f"Error fetching results: {e}")
        return redirect(url_for("index"))


@app.route("/vote", methods=["GET", "POST"])
def vote():
    if request.method == "POST":
        pem_file_path = request.form.get("pem_path")
        personal_info = request.form.get("personal_info")
        candidate_code = request.form.get("candidate_code")

        if len(personal_info) != 13:
            flash("CNP must be 13 digits!")
            return redirect(url_for("vote"))

        if len(candidate_code) != 3:
            flash("Candidate code must be 3 digits!")
            return redirect(url_for("vote"))

        try:
            tx_address = extract_address_from_pem(pem_file_path)
            signer = UserSigner.from_pem_file(Path(pem_file_path))
            proxy_provider = ProxyNetworkProvider(DEVNET_PROXY_URL)

            info_hash = hash_personal_info(personal_info)
            data = f"registerAndVote@{info_hash.encode('utf-8').hex()}@{candidate_code.encode('utf-8').hex()}"
            sender_address = Address.from_bech32(tx_address)
            receiver_address = Address.from_bech32(SC_ADDRESS)

            transaction = Transaction(
                nonce=1,  # Replace with actual nonce logic
                sender=sender_address.bech32(),
                receiver=receiver_address.bech32(),
                value=0,
                gas_limit=GAS_LIMIT,
                data=data.encode(),
                chain_id="D",
            )

            transaction_computer = TransactionComputer()
            transaction.signature = signer.sign(transaction_computer.compute_bytes_for_signing(transaction))
            proxy_provider.send_transaction(transaction)

            flash("Vote successfully cast!")
            return redirect(url_for("index"))
        except Exception as e:
            flash(f"Error submitting vote: {e}")
            return redirect(url_for("vote"))

    return render_template("vote.html")


if __name__ == "__main__":
    app.run(debug=True)
