const express = require('express');
const fetch = require('node-fetch');  // This works with node-fetch@2
const cors = require('cors');
const path = require('path');

const app = express();
app.use(express.json());
app.use(cors());
app.use(express.static(path.join(__dirname, 'public')));

// Replace with your VirusTotal API key
const VIRUSTOTAL_API_KEY = 'your_api_key_here';

app.post('/check-url', async (req, res) => {
    const urlToCheck = req.body.url;
    const virusTotalEndpoint = `https://www.virustotal.com/vtapi/v2/url/report?apikey=${VIRUSTOTAL_API_KEY}&resource=${encodeURIComponent(urlToCheck)}`;

    try {
        console.log(`Checking URL: ${urlToCheck}`);
        const response = await fetch(virusTotalEndpoint, { method: 'GET' });

        if (!response.ok) {
            console.error(`Error from VirusTotal API: ${response.statusText} (${response.status})`);
            return res.status(500).json({ message: `Error from VirusTotal API: ${response.statusText}` });
        }

        const result = await response.json();
        console.log(result);

        if (result.response_code === 1 && result.positives > 0) {
            res.json({ message: "The URL is unsafe!", positives: result.positives });
        } else if (result.response_code === 1) {
            res.json({ message: "The URL is safe!", positives: result.positives });
        } else {
            res.json({ message: "URL not found in VirusTotal database unsafe website" });
        }
    } catch (error) {
        console.error(`Error: ${error.message}`);
        res.status(500).json({ message: `Error: ${error.message}` });
    }
});

app.listen(3000, () => {
    console.log('Server running on port 3000');
});
