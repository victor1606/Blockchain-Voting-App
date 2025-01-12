#!/bin/bash

# Number of wallets to generate (default to 10 if not specified)
NUM_WALLETS=${1:-50}

# Loop to generate wallets
for ((i=1; i<=NUM_WALLETS; i++))
do
  echo "[+] Generating wallet $i..."
  mxpy wallet new --format pem --outfile "$i.pem"
  
  # Check if the wallet was created successfully
  if [[ -f "$i.pem" ]]; then
    echo "[+] Wallet $i.pem created successfully."
  else
    echo "[!] Failed to create wallet $i.pem."
  fi

  # Optional: Pause for a second to avoid overloading
#   sleep 1
done

echo "[+] Wallet generation complete."
