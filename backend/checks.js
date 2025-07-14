const axios = require('axios');

// Check URL length (Suspicious if > 75 characters)
function checkURLLength(url) {
    return url.length <= 75;
}

// Check if domain format is valid
function checkDomainValidity(url) {
    const regex = /^(https?:\/\/)?([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(:\d+)?(\/.*)?$/;
    return regex.test(url);
}

// Check URL Redirections
async function checkRedirection(url) {
    try {
        const response = await axios.get(url, { maxRedirects: 5 });
        return response.request.res.responseUrl === url;
    } catch (error) {
        console.error("Redirection check error:", error);
        return false;
    }
}

module.exports = { checkURLLength, checkDomainValidity, checkRedirection };