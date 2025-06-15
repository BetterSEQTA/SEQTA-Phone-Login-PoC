import { SeqtaAuth } from './auth';
import fetch from 'node-fetch';
import { CookieJar } from 'tough-cookie';
import fetchCookie from 'fetch-cookie';
import fs from 'fs';
import path from 'path';

import ReadLine from 'readline';

// Create logs directory if it doesn't exist
const logsDir = path.join(process.cwd(), 'logs');
if (!fs.existsSync(logsDir)) {
  fs.mkdirSync(logsDir);
}

// Create a log file with timestamp
const logFile = path.join(logsDir, `seqta-auth-${new Date().toISOString().replace(/[:.]/g, '-')}.log`);

// Logging function
function log(message: string, data?: any) {
  const timestamp = new Date().toISOString();
  const logMessage = `[${timestamp}] ${message}${data ? '\n' + JSON.stringify(data, null, 2) : ''}\n`;
  console.log(logMessage);
  fs.appendFileSync(logFile, logMessage);
}

// Create a cookie jar
const jar = new CookieJar();
// Create a fetch function that uses the cookie jar
const fetchWithCookies = fetchCookie(fetch, jar);

console.log('Welcome to the SEQTA Phone Login PoC!');
console.log('This script requires a deeplink URL to authenticate with SEQTA Learn.');
console.log('You can find this by decoding the QR code in your email from SEQTA (we have a repo just for that).');
const rl = ReadLine.createInterface({
    input: process.stdin,
    output: process.stdout
})

rl.question('Please enter the SEQTA Learn deeplink URL: ', (deeplink) => {
    rl.close();
    if (!deeplink) {
        console.error('No deeplink provided. Exiting...');
        return;
    }

    // Run the main function
    log('Script started');
    
    // Start the authentication process
    main(deeplink).catch((error: unknown) => {
        log('Unhandled error:', {
        name: error instanceof Error ? error.name : 'Unknown',
        message: error instanceof Error ? error.message : String(error),
        stack: error instanceof Error ? error.stack : undefined
        });
        console.error(error);
    });
});



async function main(deeplink: string) {
  try {
    log('Starting authentication process');
    log('Input deeplink:', deeplink);

    // Parse and validate the deeplink
    const loginRequest = SeqtaAuth.handleDeeplink(deeplink);
    log('Parsed login request:', loginRequest);

    // Set the JWT as a cookie
    log('Setting JWT cookie');
    await jar.setCookie(`JSESSIONID=${loginRequest.token}`, loginRequest.url);
    
    // First login request
    const firstLoginConfig = {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${loginRequest.token}`,
        'Referer': loginRequest.url
      },
      body: '{}'
    };
    log('First login request configuration:', firstLoginConfig);
    const firstLoginResponse = await fetchWithCookies(loginRequest.url, firstLoginConfig);
    log('First login response status:', { status: firstLoginResponse.status, statusText: firstLoginResponse.statusText });

    // Recovery request
    const recoveryConfig = {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${loginRequest.token}`,
        'Referer': loginRequest.url
      },
      body: JSON.stringify({
        mode: 'info',
        recovery: loginRequest.token
      })
    };
    log('Recovery request configuration:', recoveryConfig);
    const recoveryUrl = `${loginRequest.url.replace('/login', '/recover')}`;
    log('Sending recovery request to:', recoveryUrl);
    const recoveryResponse = await fetchWithCookies(recoveryUrl, recoveryConfig);
    log('Recovery response status:', { status: recoveryResponse.status, statusText: recoveryResponse.statusText });

    // Second login request
    const secondLoginConfig = {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${loginRequest.token}`,
        'Referer': loginRequest.url
      },
      body: JSON.stringify({ jwt: loginRequest.token })
    };
    log('Second login request configuration:', secondLoginConfig);
    const secondLoginResponse = await fetchWithCookies(loginRequest.url, secondLoginConfig);
    log('Second login response status:', { status: secondLoginResponse.status, statusText: secondLoginResponse.statusText });

    // Try to parse as JSON, but handle non-JSON responses
    const contentType = secondLoginResponse.headers.get('content-type');
    log('Response content type:', contentType);
    
    if (contentType?.includes('application/json')) {
      const data = await secondLoginResponse.json();
      log('Login successful, received JSON response:', data);
    } else {
      const text = await secondLoginResponse.text();
      log('Received non-JSON response:', text);
    }
    
    // Send heartbeat request
    const heartbeatConfig = {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${loginRequest.token}`,
        'Referer': loginRequest.url
      },
      body: JSON.stringify({ heartbeat: true })
    };
    log('Heartbeat request configuration:', heartbeatConfig);

    // Send heartbeat request
    const heartbeatUrl = `${loginRequest.url.replace('/login', '/heartbeat')}`;
    log('Sending heartbeat request to:', heartbeatUrl);
    const heartbeatResponse = await fetchWithCookies(heartbeatUrl, heartbeatConfig);
    log('Heartbeat response status:', { status: heartbeatResponse.status, statusText: heartbeatResponse.statusText });
    
    // Parse the recovery response
    const recoveryData = await recoveryResponse.json();
    log('Recovery response data:', recoveryData);

    // Save the app_link into seqtaDB
    if (recoveryData.payload && recoveryData.payload.app_link) {
      log('App link:', recoveryData.payload.app_link);
    }
    
  } catch (error: unknown) {
    log('Error occurred:', {
      name: error instanceof Error ? error.name : 'Unknown',
      message: error instanceof Error ? error.message : String(error),
      stack: error instanceof Error ? error.stack : undefined
    });
    console.error('Failed to process deeplink:', error);
  }
}