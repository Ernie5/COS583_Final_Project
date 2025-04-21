document.addEventListener("DOMContentLoaded", () => {
    const blocks = document.querySelectorAll(".result-block");

    blocks.forEach(block => {
        block.addEventListener("click", () => {
            const text = block.innerText;
            navigator.clipboard.writeText(text).then(() => {
                block.classList.add("copied");
                block.setAttribute("data-original", block.innerHTML);
                block.innerHTML = "Copied!";
                setTimeout(() => {
                    block.innerHTML = block.getAttribute("data-original");
                    block.classList.remove("copied");
                }, 1000);
            });
        });
    });
});

// Detect selection change
document.getElementById('algorithm-select').addEventListener('change', function (event) {
    const selectedAlgorithm = event.target.value;
    const heading = document.getElementById('heading');
    const messageLabel = document.getElementById('message-label');
    const messageContent = document.getElementById('message-content');
    const submitButton = document.getElementById('submit-button');

    if (selectedAlgorithm === 'dh') {
        heading.innerText = 'Demo Key Exchange';
        messageLabel.style.display = 'none';
        messageContent.style.display = 'none';
        messageContent.value = 'DH';
        submitButton.innerText = 'Demo';
    } else {
        heading.innerText = 'Encrypt Your Message';
        messageLabel.style.display = 'block';
        messageContent.style.display = 'inline-block';messageContent.value = '';
        submitButton.innerText = 'Encrypt';
    }
});