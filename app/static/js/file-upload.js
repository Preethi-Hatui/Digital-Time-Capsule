document.addEventListener('DOMContentLoaded', function() {
    const fileInputs = document.querySelectorAll('.file-upload-input');
    
    fileInputs.forEach(input => {
        const label = input.nextElementSibling;
        
        input.addEventListener('change', function(e) {
            if (this.files && this.files.length > 0) {
                label.textContent = this.files[0].name;
                
                // Optional: Show file size
                const fileSize = (this.files[0].size / 1024 / 1024).toFixed(2);
                const sizeSpan = document.createElement('span');
                sizeSpan.className = 'file-size';
                sizeSpan.textContent = ` (${fileSize} MB)`;
                label.appendChild(sizeSpan);
            }
        });
    });
});