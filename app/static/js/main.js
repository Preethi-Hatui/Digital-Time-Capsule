// Update countdown display based on unlock datetime
function updateCountdown(endTime, elementId) {
    const countdownElement = document.getElementById(elementId);
    if (!countdownElement) return;

    function renderCountdown() {
        const now = new Date();
        const diff = endTime - now;

        if (diff <= 0) {
            countdownElement.textContent = "Ready to unlock!";
            countdownElement.classList.add("text-success", "fw-bold");
            clearInterval(intervalId);
            return;
        }

        const days = Math.floor(diff / (1000 * 60 * 60 * 24));
        const hours = Math.floor((diff % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
        const minutes = Math.floor((diff % (1000 * 60 * 60)) / (1000 * 60));
        const seconds = Math.floor((diff % (1000 * 60)) / 1000);

        countdownElement.textContent = `${days}d ${hours}h ${minutes}m ${seconds}s`;
    }

    renderCountdown(); // Initial render
    const intervalId = setInterval(renderCountdown, 1000);
}

document.addEventListener('DOMContentLoaded', () => {
    // Initialize all countdowns
    document.querySelectorAll('[data-countdown]').forEach(el => {
        const endTimeStr = el.dataset.countdown;
        const endTime = new Date(endTimeStr);

        if (!el.id || isNaN(endTime.getTime())) return;
        updateCountdown(endTime, el.id);
    });

    // File input preview for name and size
    document.querySelectorAll('.file-upload-input').forEach(input => {
        const label = input.nextElementSibling;

        input.addEventListener('change', () => {
            const file = input.files?.[0];
            if (!file || !label) return;

            const sizeInKB = file.size / 1024;
            const displaySize = sizeInKB < 1024
                ? `${sizeInKB.toFixed(1)} KB`
                : `${(sizeInKB / 1024).toFixed(2)} MB`;

            label.textContent = `${file.name} (${displaySize})`;
        });
    });
});
