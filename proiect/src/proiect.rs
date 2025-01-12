#![no_std]

use multiversx_sc::imports::*;

// Candidates list with funny names and unique codes as strings
const CANDIDATES: [(&str, &str); 5] = [
    ("101", "Elon Mustache"),
    ("102", "Vlad the Voter"),
    ("103", "Angela Marketeer"),
    ("104", "Darth Trader"),
    ("105", "Tony Starkonomics"),
];

#[multiversx_sc::contract]
pub trait Proiect {
    #[init]
    fn init(&self) {}

    // Storage for voter identifiers (hashed CNPs)
    #[view(getVoterInfo)]
    #[storage_mapper("voters")]
    fn voters(&self) -> UnorderedSetMapper<ManagedBuffer<Self::Api>>;

    // Storage for wallet addresses that have voted
    #[view(getWalletVoters)]
    #[storage_mapper("wallet_voters")]
    fn wallet_voters(&self) -> UnorderedSetMapper<ManagedAddress<Self::Api>>;

    // Storage for candidate votes, now using string keys
    #[view(getResults)]
    #[storage_mapper("votes")]
    fn votes(&self, candidate_code: ManagedBuffer<Self::Api>) -> SingleValueMapper<Self::Api, u64>;

    // Voting endpoint with CNP validation
    #[endpoint(registerAndVote)]
    fn register_and_vote(&self, cnp: ManagedBuffer<Self::Api>, candidate_code: ManagedBuffer<Self::Api>) {
        let caller = self.blockchain().get_caller();

        // Ensure the wallet hasn't already voted
        require!(
            !self.wallet_voters().contains(&caller),
            "This wallet has already voted!"
        );

        // Validate candidate code length to prevent large input allocation
        require!(
            candidate_code.len() <= 10,
            "Invalid candidate code length."
        );

        // Hash the CNP for privacy
        let binding = self.crypto().sha256(&cnp);
        let cnp_hash = binding.as_managed_buffer();
        
        // Ensure the voter hasn't already voted with this CNP
        require!(
            !self.voters().contains(&cnp_hash),
            "You have already voted with this CNP!"
        );

        // Validate candidate code
        let valid_code = CANDIDATES.iter().any(|(code, _)| {
            candidate_code == ManagedBuffer::from(*code)
        });
        require!(valid_code, "Invalid candidate code.");

        // Register the wallet and CNP, then increment vote count
        self.wallet_voters().insert(caller);
        self.voters().insert(cnp_hash.clone());
        self.votes(candidate_code).update(|count| *count = count.saturating_add(1));
    }

    // View election information with candidate list
    #[view(getElectionInfo)]
    fn get_election_info(&self) -> ManagedBuffer<Self::Api> {
        let mut info = ManagedBuffer::new();

        info.append(&ManagedBuffer::from("Welcome to the Blockchain Election!\n"));
        info.append(&ManagedBuffer::from("Cast your vote for one of these candidates:\n"));

        for (code, name) in CANDIDATES.iter() {
            let candidate_info = ManagedBuffer::from(*code)
                .concat(ManagedBuffer::from(" - "))
                .concat(ManagedBuffer::from(*name))
                .concat(ManagedBuffer::from("\n"));
            require!(candidate_info.len() <= 100, "Candidate info too large.");
            info.append(&candidate_info);
        }

        info.append(&ManagedBuffer::from("\nTo vote, provide your 13-digit CNP and the candidate's code."));
        info
    }

    // Query total votes for all candidates
    #[view(getAllResults)]
    fn get_all_results(&self) -> MultiValueEncoded<Self::Api, MultiValue2<ManagedBuffer<Self::Api>, u64>> {
        let mut results = MultiValueEncoded::new();

        for (code, _) in CANDIDATES.iter() {
            let code_buffer = ManagedBuffer::from(*code);
            let vote_count = self.votes(code_buffer.clone()).get();
            results.push(MultiValue2::from((code_buffer, vote_count)));
        }

        results
    }
}
