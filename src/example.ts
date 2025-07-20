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

    const loginRequestConfig = {
      method: 'POST',
      headers: loginRequest.headers,
      body: `{
        token: ${loginRequest.token}
      }`
    }

    // Set the JWT as a cookie
    log('Setting JWT cookie');
    await jar.setCookie(`JSESSIONID=${loginRequest.token}`, loginRequest.url);

    const firstLoginRequest = await fetchWithCookies(loginRequest.url, loginRequestConfig); // Send the initial login with the token set
    log('First login resposne:', await firstLoginRequest.text());
    
    // Send the second login request. This returns information about the specific student, and confirms our login with the SEQTA server.
    const secondLoginConfig = {
      method: 'POST',
      headers: loginRequest.headers,
      body: JSON.stringify({
        jwt: loginRequest.token
      }),
    };
    log('Second login request configuration:', secondLoginConfig);
    const secondLoginResponse = await fetchWithCookies(loginRequest.url, secondLoginConfig);
    log('Second login response status:', { status: secondLoginResponse.status, statusText: secondLoginResponse.statusText });
    log('Second login response:', await secondLoginResponse.text());

    

    // Recovery request - This returns more student info
    const recoveryConfig = {
      method: 'POST',
      headers: loginRequest.headers,
      body: `{ mode: "info", recovery: ${loginRequest.token} }`
    };
    log('Recovery request configuration:', recoveryConfig);
    const recoveryUrl = `${loginRequest.url.replace('/login', '/recover')}`;
    log('Sending recovery request to:', recoveryUrl);
    const recoveryResponse = await fetchWithCookies(recoveryUrl, recoveryConfig);
    log('Recovery response status:', { status: recoveryResponse.status, statusText: recoveryResponse.statusText });
    log('Recovery resposne text:', await recoveryResponse.text());

    
    // Send heartbeat request - Check if we're alive and kicking.
    const heartbeatConfig = {
      method: 'POST',
      headers: loginRequest.headers,
      body: JSON.stringify({ heartbeat: true })
    };
    log('Heartbeat request configuration:', heartbeatConfig);

    const heartbeatUrl = `${loginRequest.url.replace('/login', '/heartbeat')}`;
    log('Sending heartbeat request to:', heartbeatUrl);
    const heartbeatResponse = await fetchWithCookies(heartbeatUrl, heartbeatConfig);
    log('Heartbeat response status:', { status: heartbeatResponse.status, statusText: heartbeatResponse.statusText });

    log('Heartbeat resposne text:', await heartbeatResponse.text());

    // The /load/profile endpoint allows us to request a new SEQTA app deeplink, allowing us to continually renew access.
    const applinkConfig = {
      method: 'POST',
      headers: loginRequest.headers,
      body: "{}"
    };

    const applinkUrl = `${loginRequest.url.replace('/login', '/load/profile')}`;
    log('Sending applink request to:', applinkUrl);
    const applinkResponse = await fetchWithCookies(applinkUrl, applinkConfig);
    log ('Applink response status:', { status: applinkResponse.status, statusText: applinkResponse.statusText });

    log('Applink response text:', await applinkResponse.text());

    
  } catch (error: unknown) {
    log('Error occurred:', {
      name: error instanceof Error ? error.name : 'Unknown',
      message: error instanceof Error ? error.message : String(error),
      stack: error instanceof Error ? error.stack : undefined
    });
    console.error('Failed to process deeplink:', error);
  }
}