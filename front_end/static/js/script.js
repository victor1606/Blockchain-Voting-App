// Function to fetch election info
function fetchElectionInfo() {
    $.get('/info', function (data) {
        let content = data.info.trim();

        // Check if the content is JSON (structured data)
        try {
            let infoData = JSON.parse(content);
            let html = '<ul>';

            for (const [key, value] of Object.entries(infoData)) {
                html += `<li><strong>${key}:</strong> ${value}</li>`;
            }

            html += '</ul>';
            $('#infoContent').html(html);

        } catch (e) {
            // If it's plain text, display it as a formatted paragraph
            $('#infoContent').html(`<p>${content.replace(/\n/g, '<br>')}</p>`);
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

