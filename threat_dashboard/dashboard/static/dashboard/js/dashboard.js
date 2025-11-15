// Dashboard sidebar toggle functionality
document.addEventListener('DOMContentLoaded', function() {
    const sidebar = document.getElementById('sidebar');
    const mainContent = document.getElementById('mainContent');
    const sidebarToggle = document.getElementById('sidebarToggle');
    const sidebarOverlay = document.getElementById('sidebarOverlay');

    // Check if we're on mobile
    function isMobile() {
        return window.innerWidth <= 992;
    }

    // Toggle sidebar
    function toggleSidebar() {
        if (isMobile()) {
            // Mobile behavior - slide sidebar over content
            sidebar.classList.toggle('open');
            sidebarOverlay.classList.toggle('active');
        } else {
            // Desktop behavior - push content
            sidebar.classList.toggle('closed');
            mainContent.classList.toggle('expanded');
        }
    }

    // Close sidebar when clicking overlay (mobile only)
    function closeSidebar() {
        sidebar.classList.remove('open');
        sidebarOverlay.classList.remove('active');
    }

    // Event listeners
    if (sidebarToggle) {
        sidebarToggle.addEventListener('click', toggleSidebar);
    }
    if (sidebarOverlay) {
        sidebarOverlay.addEventListener('click', closeSidebar);
    }

    // Handle window resize
    let resizeTimer;
    window.addEventListener('resize', function() {
        clearTimeout(resizeTimer);
        resizeTimer = setTimeout(function() {
            // Reset sidebar state on resize
            if (isMobile()) {
                sidebar.classList.remove('closed');
                mainContent.classList.remove('expanded');
                if (sidebar.classList.contains('open')) {
                    sidebarOverlay.classList.add('active');
                }
            } else {
                sidebar.classList.remove('open');
                sidebarOverlay.classList.remove('active');
            }
        }, 250);
    });

    // Active link highlighting
    const currentPath = window.location.pathname;
    const navLinks = document.querySelectorAll('.sidebar-menu .nav-link');
    
    navLinks.forEach(link => {
        if (link.getAttribute('href') === currentPath) {
            // Remove active class from all links
            navLinks.forEach(l => l.classList.remove('active'));
            // Add active class to current link
            link.classList.add('active');
        }
    });

    // Smooth scroll behavior for internal links
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function(e) {
            e.preventDefault();
            const target = document.querySelector(this.getAttribute('href'));
            if (target) {
                target.scrollIntoView({
                    behavior: 'smooth',
                    block: 'start'
                });
            }
        });
    });
});

// Initialize Charts (only on dashboard page)
function initDashboardCharts(chartData) {
    // Check if Chart.js is loaded and chart elements exist
    if (typeof Chart === 'undefined') return;
    
    const trendChartEl = document.getElementById('trendChart');
    const threatTypeChartEl = document.getElementById('threatTypeChart');
    const severityChartEl = document.getElementById('severityChart');
    
    if (!trendChartEl || !threatTypeChartEl || !severityChartEl) return;

    // Chart colors
    const colors = {
        primary: '#0d6efd',
        danger: '#dc3545',
        warning: '#ffc107',
        info: '#0dcaf0',
        success: '#198754',
        secondary: '#6c757d'
    };

    // Trend Chart
    const trendCtx = trendChartEl.getContext('2d');
    new Chart(trendCtx, {
        type: 'line',
        data: {
            labels: chartData.trend.map(d => d.date),
            datasets: [{
                label: 'Threats Detected',
                data: chartData.trend.map(d => d.count),
                borderColor: colors.danger,
                backgroundColor: colors.danger + '20',
                fill: true,
                tension: 0.4,
                borderWidth: 2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: { display: false },
                tooltip: {
                    backgroundColor: 'rgba(0, 0, 0, 0.8)',
                    padding: 12,
                    titleFont: { size: 14 },
                    bodyFont: { size: 13 }
                }
            },
            scales: {
                y: { 
                    beginAtZero: true,
                    ticks: {
                        precision: 0
                    }
                },
                x: {
                    grid: {
                        display: false
                    }
                }
            }
        }
    });

    // Threat Type Chart
    const threatTypeCtx = threatTypeChartEl.getContext('2d');
    new Chart(threatTypeCtx, {
        type: 'doughnut',
        data: {
            labels: chartData.threat_types.map(d => d.threat_type.charAt(0).toUpperCase() + d.threat_type.slice(1)),
            datasets: [{
                data: chartData.threat_types.map(d => d.count),
                backgroundColor: [
                    colors.danger,
                    colors.warning,
                    colors.info,
                    colors.primary,
                    colors.secondary
                ],
                borderWidth: 0
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: { 
                    position: 'bottom',
                    labels: {
                        padding: 15,
                        font: { size: 12 }
                    }
                },
                tooltip: {
                    backgroundColor: 'rgba(0, 0, 0, 0.8)',
                    padding: 12
                }
            }
        }
    });

    // Severity Chart
    const severityCtx = severityChartEl.getContext('2d');
    new Chart(severityCtx, {
        type: 'bar',
        data: {
            labels: chartData.severity.map(d => d.severity.charAt(0).toUpperCase() + d.severity.slice(1)),
            datasets: [{
                label: 'Count',
                data: chartData.severity.map(d => d.count),
                backgroundColor: [
                    colors.danger,
                    colors.warning,
                    colors.info,
                    colors.secondary
                ],
                borderWidth: 0,
                borderRadius: 6
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: { display: false },
                tooltip: {
                    backgroundColor: 'rgba(0, 0, 0, 0.8)',
                    padding: 12
                }
            },
            scales: {
                y: { 
                    beginAtZero: true,
                    ticks: {
                        precision: 0
                    }
                },
                x: {
                    grid: {
                        display: false
                    }
                }
            }
        }
    });
}