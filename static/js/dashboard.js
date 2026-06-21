document.addEventListener("DOMContentLoaded", function() {
    // Only fetch chart data if we are on a page with charts
    if(document.getElementById('threatTrendsChart')) {
        fetchChartData();
    }
});

function fetchChartData() {
    fetch('/api/chart-data')
        .then(response => response.json())
        .then(data => {
            renderSeverityChart(data.severities);
            renderTrendsChart(data.categories);
            
            // Update stats if they exist in the DOM
            if (document.getElementById('stat-total') && data.stats) {
                document.getElementById('stat-total').innerText = data.stats.total;
                document.getElementById('stat-active').innerText = data.stats.active;
                document.getElementById('stat-critical').innerText = data.stats.critical;
                document.getElementById('stat-malware').innerText = data.stats.malware;
            }
        })
        .catch(err => console.error("Error fetching chart data:", err));
}

let severityChartInstance = null;

function renderSeverityChart(severities) {
    const ctx = document.getElementById('severityDistributionChart');
    if(!ctx) return;
    
    // If no data, provide dummy data for visualization
    const labels = Object.keys(severities).length ? Object.keys(severities) : ['Critical', 'High', 'Medium', 'Low'];
    const data = Object.keys(severities).length ? Object.values(severities) : [12, 19, 3, 5];
    
    if (severityChartInstance) {
        severityChartInstance.destroy();
    }
    
    severityChartInstance = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: labels,
            datasets: [{
                data: data,
                backgroundColor: [
                    '#ef4444', // Danger
                    '#f59e0b', // Warning
                    '#3b82f6', // Primary
                    '#10b981'  // Success
                ],
                borderWidth: 0,
                hoverOffset: 4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: { color: '#0f172a' }
                },
                title: {
                    display: true,
                    text: 'Severity Distribution',
                    color: '#0f172a',
                    font: { size: 16 }
                }
            }
        }
    });
}

let trendsChartInstance = null;

function renderTrendsChart(categories) {
    const ctx = document.getElementById('threatTrendsChart');
    if(!ctx) return;
    
    const labels = Object.keys(categories).length ? Object.keys(categories) : ['DDoS', 'Malware', 'Phishing', 'Port Scan', 'Insider Threat'];
    const data = Object.keys(categories).length ? Object.values(categories) : [65, 59, 80, 81, 56];
    
    if (trendsChartInstance) {
        trendsChartInstance.destroy();
    }
    
    trendsChartInstance = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{
                label: 'Number of Incidents',
                data: data,
                backgroundColor: 'rgba(59, 130, 246, 0.5)',
                borderColor: '#3b82f6',
                borderWidth: 1,
                borderRadius: 5
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: {
                    beginAtZero: true,
                    grid: { color: 'rgba(0, 0, 0, 0.1)' },
                    ticks: { color: '#475569' }
                },
                x: {
                    grid: { display: false },
                    ticks: { color: '#475569' }
                }
            },
            plugins: {
                legend: { display: false },
                title: {
                    display: true,
                    text: 'Threat Categories',
                    color: '#0f172a',
                    font: { size: 16 }
                }
            }
        }
    });
}

function uploadLog() {
    const fileInput = document.getElementById('logFile');
    const file = fileInput.files[0];
    const statusDiv = document.getElementById('uploadStatus');
    
    if(!file) {
        statusDiv.innerHTML = '<div class="alert alert-warning">Please select a file first.</div>';
        return;
    }
    
    const formData = new FormData();
    formData.append('file', file);
    
    statusDiv.innerHTML = '<div class="alert alert-info"><i class="fa-solid fa-spinner fa-spin"></i> Analyzing...</div>';
    
    fetch('/predict', {
        method: 'POST',
        body: formData
    })
    .then(response => response.json())
    .then(data => {
        if(data.error) {
            statusDiv.innerHTML = `<div class="alert alert-danger">Error: ${data.error}</div>`;
        } else {
            statusDiv.innerHTML = `<div class="alert alert-success"><i class="fa-solid fa-check"></i> ${data.message}</div>`;
            // Refresh chart data after upload
            fetchChartData();
        }
    })
    .catch(error => {
        statusDiv.innerHTML = `<div class="alert alert-danger">Error: ${error.message}</div>`;
    });
}

function startSniffer() {
    const statusDiv = document.getElementById('uploadStatus');
    const btn = document.getElementById('snifferBtn');
    
    btn.disabled = true;
    btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Starting...';
    
    fetch('/start_sniffer', { method: 'POST' })
    .then(response => response.json())
    .then(data => {
        statusDiv.innerHTML = `<div class="alert alert-success"><i class="fa-solid fa-satellite-dish pulse"></i> ${data.message} Dashboard will auto-refresh every 5 seconds.</div>`;
        btn.innerHTML = '<i class="fa-solid fa-satellite-dish"></i> Sniffer Running';
        btn.classList.replace('btn-warning', 'btn-success');
        
        // Auto-refresh chart data every 5 seconds
        setInterval(fetchChartData, 5000);
    })
    .catch(error => {
        btn.disabled = false;
        btn.innerHTML = '<i class="fa-solid fa-satellite-dish"></i> Start Live Sniffer';
        statusDiv.innerHTML = `<div class="alert alert-danger">Error starting sniffer: ${error.message}</div>`;
    });
}

function resetData() {
    if(!confirm("Are you sure you want to delete all threat data? This cannot be undone.")) return;
    
    const btn = document.getElementById('resetBtn');
    const statusDiv = document.getElementById('uploadStatus');
    
    btn.disabled = true;
    btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Resetting...';
    
    fetch('/api/reset', { method: 'POST' })
    .then(response => response.json())
    .then(data => {
        btn.disabled = false;
        btn.innerHTML = '<i class="fa-solid fa-trash"></i> Reset Data';
        
        if(data.error) {
            statusDiv.innerHTML = `<div class="alert alert-danger">Error: ${data.error}</div>`;
        } else {
            statusDiv.innerHTML = `<div class="alert alert-success"><i class="fa-solid fa-check"></i> ${data.message}</div>`;
            fetchChartData(); // Instantly refresh charts to 0
        }
    })
    .catch(error => {
        btn.disabled = false;
        btn.innerHTML = '<i class="fa-solid fa-trash"></i> Reset Data';
        statusDiv.innerHTML = `<div class="alert alert-danger">Error resetting data: ${error.message}</div>`;
    });
}
