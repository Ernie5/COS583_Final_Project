document.addEventListener("DOMContentLoaded", () => {
    const blocks = document.querySelectorAll(".result-block");

    blocks.forEach(block => {
        block.addEventListener("click", () => {
            const value = block.querySelector(".result-value");
            const text = value.innerText;
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
        heading.innerText = 'Diffie Hellman Demo Key Exchange';
        messageLabel.style.display = 'none';
        messageContent.style.display = 'none';
        messageContent.value = 'DH';
        submitButton.innerText = 'Demo';
    } else if (selectedAlgorithm === 'ml_kem') {
        heading.innerText = 'ML_KEM Demo Key Exchange';
        messageLabel.style.display = 'none';
        messageContent.style.display = 'none';
        messageContent.value = 'ML_KEM';
        submitButton.innerText = 'Demo';
    } else {
        heading.innerText = 'Encrypt Your Message';
        messageLabel.style.display = 'block';
        messageContent.style.display = 'inline-block';messageContent.value = '';
        submitButton.innerText = 'Encrypt';
    }
});

document.addEventListener("DOMContentLoaded", () => {

    const algoSel   = document.getElementById('algorithm-select');
    const opSet     = document.getElementById('op-fieldset');
    const opRadios  = [...document.getElementsByName('operation')];
    const plainGrp  = document.getElementById('plain-group');
    const aesExtra  = document.getElementById('aes-extra');
    const rsaExtra  = document.getElementById('rsa-extra');

    function refresh() {
        const algo = algoSel.value;
        const op   = opRadios.find(r => r.checked)?.value || 'encrypt';

        const needsOp = (algo === 'aes' || algo === 'rsa');
        // show / hide the Encrypt-Decrypt chooser
        opSet.classList.toggle('hidden', !needsOp);

        // ensure "encrypt" is selected when we hide the fieldset
        if (!needsOp) opRadios.find(r => r.value === 'encrypt').checked = true;

        // plaintext box only needed for encryption
        const effectiveOp = needsOp ? op : 'encrypt';
        plainGrp.style.display = (effectiveOp === 'encrypt') ? 'block' : 'none';

        // AES / RSA specific decryption inputs
        aesExtra.classList.toggle('hidden', !(algo === 'aes' && effectiveOp === 'decrypt'));
        rsaExtra.classList.toggle('hidden', !(algo === 'rsa' && effectiveOp === 'decrypt'));
    }

    // initial state
    refresh();

    // listeners
    algoSel.addEventListener('change', refresh);
    opRadios.forEach(r => r.addEventListener('change', refresh));
});
