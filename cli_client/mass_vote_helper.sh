#!/bin/bash

# Path to the wallets directory
WALLETS_DIR="./wallets"

# Define the range of voting options (adjust as needed)
VOTE_OPTIONS=(1 2 3 4 5)

# Function to generate a random 9-digit personal ID
generate_random_personal_info() {
  echo $(( RANDOM % 900000000 + 100000000 ))
}

# Function to select a random voting option
generate_random_vote_option() {
  local len=${#VOTE_OPTIONS[@]}
  echo ${VOTE_OPTIONS[$RANDOM % len]}
}

# Loop through all .pem files in the wallets directory
for pem_file in "$WALLETS_DIR"/*.pem; do
  if [[ -f "$pem_file" ]]; then
    # Generate random personal data and vote option
    personal_info=$(generate_random_personal_info)
    vote_option=$(generate_random_vote_option)

    echo "[+] Voting with wallet: $pem_file"
    echo "[+] Personal Info: $personal_info | Voting Option: $vote_option"

    # Call the Python voting client
    python3 client.py vote "$pem_file" "$personal_info" "$vote_option"

    # Optional: Pause for a second to avoid spamming the network
    sleep 1
  fi
done

echo "[+] Voting process completed for all wallets."
