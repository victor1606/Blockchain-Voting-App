// Function to fetch election info
function fetchElectionInfo() {
    $.get('/info', function (data) {
        let content = data.info.trim();

        // Display the raw info in the infoContent section
        $('#infoContent').html(`<p>${content.replace(/\n/g, '<br>')}</p>`);

        // Extract candidate codes and names from the string
        const candidateDropdown = $('#candidate_code');
        candidateDropdown.empty(); // Clear existing options
        candidateDropdown.append('<option value="">Select a candidate...</option>');

        const candidatePattern = /^\s*(\d{3})\s*-\s*(.+)$/gm;  // Matches only 3-digit codes at the start of lines
        let match;

        while ((match = candidatePattern.exec(content)) !== null) {
            const code = match[1].trim();
            const name = match[2].trim();
            candidateDropdown.append(`<option value="${code}">${name} (${code})</option>`);
        }

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

function toggleLoading(isLoading) {
    const loader = document.getElementById('loader');
    const buttons = document.querySelectorAll('#buttonGroup button');

    if (isLoading) {
        loader.style.display = 'block';
        buttons.forEach(button => button.disabled = true); // Disable buttons
    } else {
        loader.style.display = 'none';
        buttons.forEach(button => button.disabled = false); // Enable buttons
    }
}

function displayLogs(logs, type = 'info') {
    const messagesDiv = document.getElementById('messages');
    messagesDiv.innerHTML = '';  // Clear previous messages

    logs.forEach(log => {
        const messageElement = document.createElement('div');
        messageElement.className = `alert alert-${type}`;
        messageElement.textContent = log;
        messagesDiv.appendChild(messageElement);
    });
}

$(document).ready(function () {
    $('#voteForm').on('submit', function (e) {
        e.preventDefault();

        let formData = new FormData(this);
        toggleLoading(true);
        $.ajax({
            url: '/vote',
            method: 'POST',
            data: formData,
            processData: false,
            contentType: false,
            success: function (response) {
                const logType = response.status === 'success' ? 'success' : 'danger';
                displayLogs(response.logs, logType);
                toggleLoading(false);
            },
            error: function (xhr) {
                displayLogs(["An error occurred. Please try again."], 'danger');
                toggleLoading(false);
            }
        });
    });
});

