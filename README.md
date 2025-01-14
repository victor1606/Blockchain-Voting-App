# Blockchain-Voting-App
Decentralized MultiversX blockchain voting app.

Team members: Calugaritoiu Ion-Victor & Albuica Sergiu-Mihail

## 1. Purpose of the Project:
To develop a decentralized voting application using the MultiversX blockchain. The
project will enable secure, transparent, and tamper-proof voting processes for
small-scale elections or polls.
## 2. Features:
* Transparency: MultiversX blockchain ensures every vote is recorded and
veriable.
* Security: Votes cannot be tampered with or deleted after submission.
* Ease of Use: Participants can vote using a simple interface, and results are
automatically counted.
## 3. Components of the Project:
### A. Smart Contract:
* A Rust smart contract deployed on the MultiversX blockchain that:
* Manages voter registration.
* Allows users to cast votes for predened options.
* Automatically counts and publishes results.
* Limits one vote per registered wallet address and voter government ID
(CNP).
### B. Flask web app deployed on Azure:
#### Back-End:
* Fetching Election Info: Retrieves candidate details from the smart contract and saves them locally.
* Voting: Validates input, hashes the CNP, and submits a transaction to the blockchain.
* Fetching Results: Retrieves vote counts for all candidates from the smart contract.
* ID Validation: Used Tesseract for automatic CNP extraction using OCR.
* Utilities: Handles wallet address extraction, data hashing, and error feedback.
#### Front-End:
* Features responsive UI for a good cross platform UX.
* Enables voter wallet upload for transaction signature.
* Allows user to upload government ID.
* Displays voting options.
* Displays total vote count per candidate
* Allows users to cast votes by selecting chosen candidate
### C. Python CLI client:
Gives users the same functionality as the web-app, but in a portable local Python
script.
## 4. Microsoft Azure deployment:
The app is hosted on Microsoft Azure and is available at the following address:

http://20.151.161.188:5000
## 5. References:
* https://docs.multiversx.com/sdk-and-tools/sdk-py/sdk-py-cookbook/
* https://docs.multiversx.com/sdk-and-tools/sdk-rust
* https://docs.multiversx.com/developers/meta/sc-cong/#single-contract-conguration
* https://docs.multiversx.com/developers/smart-contracts
* https://github.com/pallets/ask/tree/main/examples/tutorial
* https://github.com/multiversx/mx-contracts-rs/tree/main
