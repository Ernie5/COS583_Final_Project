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
