document.addEventListener('DOMContentLoaded', () => {
    // 1. Animated Metric Counter
    const counters = document.querySelectorAll('.counter-val');
    counters.forEach(counter => {
        const target = +counter.getAttribute('data-target');
        const speed = 50; // lower = faster

        const updateCount = () => {
            const count = +counter.innerText.replace(/,/g, '');
            const inc = Math.ceil(target / speed);

            if (count < target) {
                counter.innerText = (count + inc).toLocaleString();
                setTimeout(updateCount, 20);
            } else {
                counter.innerText = target.toLocaleString();
            }
        };
        updateCount();
    });

    // 2. Active Navigation Link Highlighting
    const currentPath = window.location.pathname;
    const navLinks = document.querySelectorAll('.nav-link-custom');
    
    navLinks.forEach(link => {
        if (link.getAttribute('href') === currentPath) {
            link.classList.add('active', 'border-start', 'border-info', 'ps-3');
            link.style.color = '#00f2fe';
            link.style.background = 'rgba(0, 242, 254, 0.1)';
        }
    });
});

// Toast notification trigger for live threats
function showThreatAlert(title, message) {
    const alertBox = document.createElement('div');
    alertBox.className = 'glass-card border-danger text-light p-3 position-fixed top-0 end-0 m-4';
    alertBox.style.zIndex = '9999';
    alertBox.style.maxWidth = '320px';
    alertBox.innerHTML = `
        <div class="d-flex align-items-center mb-1">
            <span class="pulse-red me-2"></span>
            <strong class="text-danger me-auto">${title}</strong>
            <button type="button" class="btn-close btn-close-white btn-sm" onclick="this.parentElement.parentElement.remove()"></button>
        </div>
        <div class="small text-muted">${message}</div>
    `;
    document.body.appendChild(alertBox);
    setTimeout(() => { if (alertBox) alertBox.remove(); }, 5000);
}