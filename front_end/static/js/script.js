// Function to fetch election info
function fetchElectionInfo() {
    $.get('/info', function (data) {
        $('#infoContent').html(`<pre>${data.info}</pre>`);
    }).fail(function () {
        $('#infoContent').html('<span class="text-danger">Failed to load election info.</span>');
    });
}

// Function to fetch election results
function fetchElectionResults() {
    $.get('/results', function (data) {
        let html = '<ul>';
        data.results.forEach(result => {
            html += `<li>Code: ${result.code}, Votes: ${result.votes}</li>`;
        });
        html += '</ul>';
        $('#resultsContent').html(html);
    }).fail(function () {
        $('#resultsContent').html('<span class="text-danger">Failed to load election results.</span>');
    });
}

// Fetch data on page load
$(document).ready(function () {
    fetchElectionInfo();
    fetchElectionResults();
});

// Refresh data on button click
$('#infoBtn').click(function () {
    fetchElectionInfo();
});

$('#resultsBtn').click(function () {
    fetchElectionResults();
});

// Handle Vote Form Submission
$('#voteForm').submit(function (e) {
    e.preventDefault(); // Prevent the default form submission (redirection)

    const formData = new FormData(this);

    $.ajax({
        url: '/vote', // Target endpoint
        method: 'POST',
        data: formData,
        processData: false,
        contentType: false,
        success: function (response) {
            // Display success response dynamically
            let html = '<ul>';
            html += `<li><strong>Transaction Hash:</strong> ${response.transaction_hash}</li>`;
            html += `<li><strong>Message:</strong> ${response.message}</li>`;
            html += `<li><strong>Smart Contract Response:</strong> ${response.smart_contract_response}</li>`;
            html += '</ul>';
            $('#itachi').html(html); // Display in resultsContent container
        },
        error: function (xhr) {
            // Display error response dynamically
            const errorMessage = xhr.responseJSON?.message || 'An unexpected error occurred.';
            $('#itachi').html(`<span class="text-danger">${errorMessage}</span>`);
        },
    });
});
