// Initialize Dashboard Analytics Charts
function initDashboardCharts(sectorLabels, sectorValues, attackLabels, attackValues) {
    const chartText = '#a8c1bd';
    const chartGrid = 'rgba(168, 193, 189, 0.14)';
    const chartFont = { family: 'Space Grotesk', size: 11 };
    const sectorCtx = document.getElementById('sectorChart')?.getContext('2d');
    if (sectorCtx) {
        new Chart(sectorCtx, {
            type: 'bar',
            data: {
                labels: sectorLabels,
                datasets: [{
                    label: 'Mean Risk Score',
                    data: sectorValues,
                    backgroundColor: 'rgba(45, 212, 191, 0.48)',
                    borderColor: '#5eead4',
                    borderWidth: 1.5,
                    borderRadius: 4
                }]
            },
            options: {
                responsive: true,
                scales: {
                    y: { beginAtZero: true, grid: { color: chartGrid }, ticks: { color: chartText, font: chartFont } },
                    x: { grid: { display: false }, ticks: { color: chartText, font: chartFont } }
                },
                plugins: { legend: { labels: { color: chartText, font: chartFont, boxWidth: 28 } } }
            }
        });
    }

    const pieCtx = document.getElementById('attackPieChart')?.getContext('2d');
    if (pieCtx) {
        new Chart(pieCtx, {
            type: 'doughnut',
            data: {
                labels: attackLabels,
                datasets: [{
                    data: attackValues,
                    backgroundColor: ['#ff0055', '#00f2fe', '#ffb703', '#10b981', '#a855f7'],
                    borderWidth: 0
                }]
            },
            options: { responsive: true, plugins: { legend: { position: 'bottom', labels: { color: chartText, font: chartFont, padding: 14 } } } }
        });
    }
}

// Initialize Interactive Vis.js Knowledge Graph
function initKnowledgeGraph(containerId, graphData) {
    const container = document.getElementById(containerId);
    if (!container) return;

    const options = {
        nodes: {
            shape: 'dot',
            size: 16,
            font: { color: '#e2e8f0', size: 12 }
        },
        edges: {
            color: { color: 'rgba(0, 242, 254, 0.4)', highlight: '#ff0055' },
            width: 1.5
        },
        physics: {
            barnesHut: { gravitationalConstant: -3000, springLength: 95 }
        }
    };

    new vis.Network(container, graphData, options);
}