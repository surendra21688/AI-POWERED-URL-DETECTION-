const express = require('express');
const fetch = require('node-fetch');
const cors = require('cors');
const path = require('path');

const app = express();

app.use(express.json());
app.use(cors());
app.use(express.static(path.join(__dirname, 'public')));

// Use environment variable for the API key
const VIRUSTOTAL_API_KEY = process.env.VIRUSTOTAL_API_KEY;

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
         return res.json({ message: "The URL is unsafe!", positives: result.positives });
      } else if (result.response_code === 1) {
         return res.json({ message: "The URL is safe!", positives: result.positives });
      } else {
         return res.json({ message: "URL not found in VirusTotal database. Looks safe." });
      }
   } catch (error) {
      console.error(`Error: ${error.message}`);
      return res.status(500).json({ message: `Error: ${error.message}` });
   }
});

app.listen(3000, () => {
   console.log('Server running on port 3000');
});
