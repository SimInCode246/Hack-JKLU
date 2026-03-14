const fs = require('fs');

(async () => {
  const base = 'http://localhost:5000';

  const run = async () => {
    console.log('Testing new vulnerability patterns...');
    const testCode = `
      // Test various vulnerabilities
      const userInput = req.body.input;
      
      // SSRF
      const axios = require('axios');
      axios.get(userInput);
      
      // Insecure deserialization
      const data = JSON.parse(userInput);
      
      // Hardcoded secret
      const apiKey = "sk-1234567890abcdef";
      
      // SQL injection
      const query = "SELECT * FROM users WHERE id = " + userInput;
      
      // Path traversal
      const fs = require('fs');
      fs.readFileSync(userInput);
      
      // Weak crypto
      const crypto = require('crypto');
      crypto.createHash('md5');
      
      // Insecure random
      const token = Math.random().toString();
      
      // Missing helmet
      // (no helmet middleware)
    `;
    
    const codeResp = await fetch(base + '/api/scan/code', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code: testCode, filename: 'test.js' })
    });
    const codeJson = await codeResp.json();
    console.log('Code scan status', codeResp.status);
    console.log('Vulnerabilities found:', codeJson.vulnerabilities?.length);
    console.log('AI findings:', codeJson.aiFindings?.length);
    codeJson.vulnerabilities?.forEach(v => console.log(`- ${v.title} (${v.severity})`));

    console.log('\nTesting npm dependency scan...');
    const pkg = {
      name: 'test',
      version: '1.0.0',
      dependencies: {
        lodash: '4.17.20'
      }
    };
    const depResp = await fetch(base + '/api/scan/dependencies', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ content: JSON.stringify(pkg, null, 2), filename: 'package.json' })
    });
    const depJson = await depResp.json();
    console.log('NPM scan status', depResp.status);
    console.log('Package manager:', depJson.packageManager);
    console.log('Vuln count:', depJson.vulnerableCount, 'Deps:', depJson.totalDependencies);

    console.log('\nTesting Python requirements scan...');
    const requirements = `requests==2.25.1
Django==3.1.0
flask==1.1.0`;
    const pyResp = await fetch(base + '/api/scan/dependencies', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ content: requirements, filename: 'requirements.txt' })
    });
    const pyJson = await pyResp.json();
    console.log('Python scan status', pyResp.status);
    console.log('Package manager:', pyJson.packageManager);
    console.log('Deps found:', pyJson.totalDependencies);

    console.log('\nTesting Ruby Gemfile scan...');
    const gemfile = `source 'https://rubygems.org'

gem 'rails', '6.0.0'
gem 'nokogiri', '1.10.0'`;
    const rbResp = await fetch(base + '/api/scan/dependencies', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ content: gemfile, filename: 'Gemfile' })
    });
    const rbJson = await rbResp.json();
    console.log('Ruby scan status', rbResp.status);
    console.log('Package manager:', rbJson.packageManager);
    console.log('Deps found:', rbJson.totalDependencies);
  };

  if (!global.fetch) {
    global.fetch = require('node-fetch');
  }

  try {
    await run();
  } catch (err) {
    console.error('Error running scan script:', err);
    process.exit(1);
  }
})();
