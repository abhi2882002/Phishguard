async function checkURL() {
    const url = document.getElementById('urlInput').value;

    if (!url) {
        alert("Please enter a URL.");
        return;
    }

    try {
        const response = await fetch('http://localhost:5001/check-url', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url })
        });

        if (!response.ok) {
            throw new Error(`HTTP error! Status: ${response.status}`);
        }

        const data = await response.json();
        console.log("API Response:", data); // Debugging
        document.getElementById('result').innerText = JSON.stringify(data, null, 2);
    } catch (error) {
        console.error("Error checking the URL:", error);
        document.getElementById('result').innerText = "Error checking the URL";
    }
}