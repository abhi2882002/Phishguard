const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const axios = require('axios');
const cheerio = require('cheerio');
const { checkURLLength, checkDomainValidity, checkRedirection } = require('./checks');

const app = express();

//		express: Creates the web server.
//		cors: Enables Cross-Origin Resource Sharing (CORS) so frontend can make requests to the backend.
//		bodyParser: Parses incoming JSON data.
//		axios: Fetches data from URLs.
//		cheerio: Helps analyze the HTML content of a webpage.
//		checkURLLength, checkDomainValidity, checkRedirection: These functions (imported from checks.js) perform basic URL safety checks.
// Middleware
app.use(cors());
app.use(bodyParser.json());

// Root Route
app.get('/', (req, res) => {
    res.send("PhishGuard Backend is Running!");
});

// Function to analyze redirection safety
async function checkRedirectionSafety(url) {
    try {
        const response = await axios.get(url, { maxRedirects: 5 });
        const finalURL = response.request.res.responseUrl;

        const originalDomain = new URL(url).hostname.replace('www.', '');
        const finalDomain = new URL(finalURL).hostname.replace('www.', '');

        return originalDomain === finalDomain; // Safe if domains match
    } catch (error) {
        console.error("Error in redirection check:", error.message);
        return false; // Mark as unsafe if an error occurs
    }
}

// Function to analyze source code for phishing indicators
async function analyzeSourceCode(url) {
    try {
        const response = await axios.get(url, { timeout: 5000 });
        const html = response.data;

        if (!html || html.length === 0) {
            return { isPhishing: true, riskScore: 10 }; // High risk if page is inaccessible
        }

        const $ = cheerio.load(html);
        let riskScore = 0;

        // Check for suspicious form actions
        $('form').each((_, form) => {
            const action = $(form).attr('action');
            if (action && action.includes('http') && !action.includes(url)) {
                riskScore += 3; // Form submits to a different domain (phishing risk)
            }
        });

        // Check for too many hidden input fields
        if ($('input[type="hidden"]').length > 5) {
            riskScore += 2;
        }

        // Check for obfuscated JavaScript
        if (html.includes('eval(') || html.includes('atob(') || html.includes('document.write(')) {
            riskScore += 3;
        }

        // Check for phishing keywords in metadata
        const phishingKeywords = ['password', 'bank', 'login', 'secure', 'verification'];
        $('meta').each((_, meta) => {
            const content = $(meta).attr('content');
            if (content && phishingKeywords.some(word => content.toLowerCase().includes(word))) {
                riskScore += 2;
            }
        });

        return { isPhishing: riskScore > 5, riskScore };
    } catch (error) {
        console.error('Error analyzing source code:', error.message);
        return { isPhishing: true, riskScore: 10 }; // Default high risk if request fails
    }
}

// Main API endpoint
app.post('/check-url', async (req, res) => {
    const { url } = req.body;

    if (!url) {
        console.log("❌ No URL provided");
        return res.status(400).json({ error: "URL is required" });
    }

    console.log(`🔍 Checking URL: ${url}`);

    try {
        const isRedirectionSafe = await checkRedirectionSafety(url);
        const { isPhishing: isSourcePhishing, riskScore } = await analyzeSourceCode(url);

        const results = {
            urlLength: checkURLLength(url),
            domainValid: checkDomainValidity(url),
            redirectionSafe: isRedirectionSafe,
            sourceCodePhishing: isSourcePhishing,
            riskScore
        };

        const isSafe = results.urlLength && results.domainValid && results.redirectionSafe && !isSourcePhishing;

        // 🔴 Log full report in the terminal
        console.log("--------------------------------------------------");
        console.log(`📝 Full Report for: ${url}`);
        console.log(`✅ URL Length Valid: ${results.urlLength}`);
        console.log(`✅ Domain Valid: ${results.domainValid}`);
        console.log(`🔄 Redirection Safe: ${results.redirectionSafe}`);
        console.log(`🔍 Source Code Phishing Detected: ${results.sourceCodePhishing}`);
        console.log(`⚠️ Risk Score: ${results.riskScore}`);
        console.log(`🔎 Final Verdict: ${isSafe ? "✔ Legitimate" : "❌ Phishing"}`);
        console.log("--------------------------------------------------\n");

        res.json({ isSafe, details: results });

    } catch (error) {
        console.error(`❌ Error checking URL: ${url}`, error);
        res.status(500).json({ error: "Internal Server Error" });
    }
});

// Start Server
const PORT = process.env.PORT || 5001;
app.listen(PORT, () => console.log(`✅ Server running on port ${PORT}`));