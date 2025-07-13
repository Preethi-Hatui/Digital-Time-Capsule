function updateCountdown(endTime, elementId) {
    const countdownElement = document.getElementById(elementId);
    if (!countdownElement) return;

    function update() {
        const now = new Date();
        const diff = endTime - now;

        if (diff <= 0) {
            countdownElement.innerHTML = "Ready to unlock!";
            return;
        }

        const days = Math.floor(diff / (1000 * 60 * 60 * 24));
        const hours = Math.floor((diff % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
        const minutes = Math.floor((diff % (1000 * 60 * 60)) / (1000 * 60));
        const seconds = Math.floor((diff % (1000 * 60)) / 1000);

        countdownElement.innerHTML = `${days}d ${hours}h ${minutes}m ${seconds}s`;
    }

    update();
    setInterval(update, 1000);
}

// Initialize all countdowns on page load
document.addEventListener('DOMContentLoaded', function() {
    document.querySelectorAll('[data-countdown]').forEach(el => {
        const endTime = new Date(el.dataset.countdown);
        updateCountdown(endTime, el.id);
    });
});