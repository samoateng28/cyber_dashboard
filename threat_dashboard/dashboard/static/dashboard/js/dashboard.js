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
    sidebarToggle.addEventListener('click', toggleSidebar);
    sidebarOverlay.addEventListener('click', closeSidebar);

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