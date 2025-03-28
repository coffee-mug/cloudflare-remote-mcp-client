import { Hono } from 'hono';
import { getCookie } from 'hono/cookie';
import { serveStatic } from 'hono/serve-static';
import { logger } from 'hono/logger';
import { cors } from 'hono/cors';
import { html } from 'hono/html';
import { setCookie, getCookie } from 'hono/cookie';
import { SSEClientTransport, SseError } from '@modelcontextprotocol/sdk/client/sse.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { stream, streamText, streamSSE } from 'hono/streaming'

// Configuration
const config = {
  mcpServerUrl: 'http://localhost:8787',
  clientId: 'your-client-id',
  redirectUri: 'http://localhost:4000/oauth/callback',
  sessionCookieName: 'mcp_session',
  authUrl: 'http://localhost:8787/authorize'
};

// Initialize Hono app
const app = new Hono();
let client;

// Middleware
app.use('*', logger());
app.use('*', cors());

// Foe dev only, move to KV
const sessions = new Map();


// Home route
app.get('/', (c) => {
  const sessionId = getCookie(c, config.sessionCookieName);

  return c.html(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>MCP Client</title>
      <style>
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }
        button { padding: 10px 15px; background: #4CAF50; color: white; border: none; border-radius: 4px; cursor: pointer; }
        #tools { margin-top: 20px; }
      </style>
    </head>
    <body>
      <h1>MCP Client</h1>
      <button id="listTools">List Tools</button>
      <div id="tools"></div>
      <div id="messages"></div>

      <script>
        const sessionId = "${sessionId || ''}";
        
        document.getElementById('listTools').addEventListener('click', async () => {
          const messagesDiv = document.getElementById('messages');
          messagesDiv.innerHTML = 'Connecting to MCP server...';

          try {
            // Start SSE connection
            const eventSource = new EventSource('/sse' + (sessionId ? '?sessionId=' + sessionId : ''));

            eventSource.onopen = e => {
              console.log("Opened", e)
            }
            
            eventSource.onmessage = async (event) => {
              const data = JSON.parse(event.data);
              messagesDiv.innerHTML += '<p>' + JSON.stringify(data) + '</p>';

              console.log("Message type", data.type)
              
              // Handle specific message types here
              if (data.type === 'tools') {
                const toolsDiv = document.getElementById('tools');
                toolsDiv.innerHTML = '<h3>Available Tools:</h3><ul>' + 
                  data.tools.map(tool => '<li>' + tool.name + '</li>').join('') + 
                  '</ul>';
              }
              
              if (data.type === 'auth_required') {
                // Redirect to authorization
                window.location.href = data.authUrl;
              }

              if (data.type === 'client_registration') {
                console.log(event.data)
                const data = JSON.parse(event.data);
                messagesDiv.innerHTML += '<p>' + JSON.stringify(data) + '</p>';

                // Redirect to authorization
                console.log(data)
                const register = await fetch(data.registrationInfos.register_endpoint, {
                  method: "POST",
                  body: JSON.stringify(data.registrationInfos)
                })

                const registration = await register.json();

                console.log("registered object", registration)



                // For now we use the "plain" method for sharing the code_verifier, 
                // it's obivously insecure and must be adapted to use S256 instead

                const codeChallenge = [...crypto.getRandomValues(new Uint8Array(20))].map(m => ('0' + m.toString(16)).slice(-2)).join('')
                document.cookie = "code_challenge=" + codeChallenge;

                // Sharing client_id too
                document.cookie = "client_id="+registration.client_id;

                const authSearchParams = new URLSearchParams({
                  response_type: "code",
                  client_id: registration.client_id,
                  code_challenge: codeChallenge,
                  code_challenge_method: "plain",
                  redirect_uri: registration.redirect_uris[0]
                })


                console.log(authSearchParams)
                window.location.href = "http://localhost:8787/authorize?"+ authSearchParams.toString()
                
              }
            };
            
            eventSource.onerror = (error) => {
              messagesDiv.innerHTML += '<p class="error">Connection error: ' + JSON.stringify(error) + '</p>';
              eventSource.close();
            };
          } catch (error) {
            messagesDiv.innerHTML = '<p class="error">Error: ' + JSON.stringify(error) + '</p>';
          }
        });
      </script>
    </body>
    </html>
  `);
});

// SSE endpoint to establish connection with MCP server
app.get('/sse', async (c) => {
  const sessionId = getCookie(c, config.sessionCookieName)

  console.log("IN SSE")

  // Set up SSE response headers
  c.header('Content-Type', 'text/event-stream');
  c.header('Cache-Control', 'no-cache');
  c.header('Connection', 'keep-alive');

  console.log('In sse', sessionId)

  console.log("Sessions", [...sessions.entries()])
  
  // Create a new session if none exists
  const session = sessionId && sessions.has(sessionId) 
    ? sessions.get(sessionId) 
    : { id: [...crypto.getRandomValues(new Uint8Array(20))].map(m=>('0'+m.toString(16)).slice(-2)).join('') };

    console.log("SessionId", sessionId)
  
  if (!sessionId) {
    sessions.set(session.id, session);

    console.log("Sessions after sessions.set", [...sessions.entries()])

    // Set session cookie for the client
    setCookie(c, config.sessionCookieName, session.id, {
      httpOnly: true,
      secure: false,
      sameSite: 'Lax',
      maxAge: 60 * 60 * 24 // 24 hours
    });
  }
  
  // Set up the writer for sending events
  // Connect to MCP server using SSE transport
  const headers = {}

  if( session.accessToken) {
    headers['authorization'] = `Bearer ${session.accessToken}`
  }
  try {
    console.log('session', session, "session token", session.accessToken)

    const serverUrl = new URL(`${config.mcpServerUrl}/sse`)
    const transport = new SSEClientTransport(serverUrl, {
      // Include any necessary authentication here if required
      eventSourceInit: {
        fetch: (url, init) => fetch(url, { ...init, headers }),
      },
      requestInit: {
        headers
      } 
    });

    // Attempt to connect without auth
    try {
      if (!client) {
        // Initialize MCP client with the transport
        client = new Client({ name: "mcp-client", version: "0.0.1" });
        console.log('Trying to connect')
        const res = await client.connect(transport)
        console.log("Connection",res)
      } else {
        console.log('Trying to list tools')
        const res = await client.connect(transport)
        const tools = await client.listTools();


        return streamSSE(c, 
          async (stream) => {
            try {
              await stream.write(`data: ${JSON.stringify({ tools, type: "tools" })}\n\n`)
            } catch(e) {
              console.log(e)
            }
          },
          (err, stream) => {
            stream.writeln('error occured with streamSSE')
            console.error(err)
          })
      }

      //console.log("tools", tools)
    } catch(e) {
      console.log("Error")
      if (e instanceof SseError) {
        // Need auth
        console.log(e)
        if (e.code === 401) {
          // Construct auth URL
          console.log("Unauthorized", e)
          if (!session.accessToken) {
            // New client
            const registrationInfos = {
              "redirect_uris":["http://localhost:4000/oauth/callback"],
              "token_endpoint_auth_method":"none",
              "grant_types":["authorization_code","refresh_token"],
              "response_types":["code"],
              "client_name":"MCP Client",
              "client_uri":"https://github.com/modelcontextprotocol/inspector",
              "register_endpoint": "http://localhost:8787/register"
            }

            return streamSSE(c, 
              async (stream) => {
                try {
                  await stream.write(`data: ${JSON.stringify({ registrationInfos, type: "client_registration" })}\n\n`)
                } catch(e) {
                  console.log(e)
                }
              },
              (err, stream) => {
                stream.writeln('error occured with streamSSE')
                console.error(err)
              })
          } else {
            // Expired token
          return streamSSE(c, 
            async (stream) => {
              try {
                await stream.write(`data: ${JSON.stringify({ authUrl: config.authUrl, type: "auth_required" })}\n\n`)
              } catch(e) {
                console.log(e)
              }
            },
            (err, stream) => {
              stream.writeln('error occured with streamSSE')
              console.error(err)
            })
          }
        }

        console.log("SSEError", e)
      }
      console.log(e)
    }
    // Handle transport events
  } catch (error) {
    return streamText(c, async (stream) => {
      console.log("In error", error)
      await stream.write(`data: ${JSON.stringify({ type: 'error', message: error.message })}\n\n`);
    })
  }

});

// OAuth callback endpoint
app.get('/oauth/callback', async (c) => {
  const { code } = c.req.query();

  const codeVerifier = getCookie(c, "code_challenge")
  const clientId = getCookie(c, "client_id")
  const sessionId = getCookie(c, config.sessionCookieName)
  
  if (!code) {
    return c.redirect('/?error=missing_parameters');
  }

  console.log(`In token call: code_verifier = ${codeVerifier}, code: ${code}, client_id: ${clientId}`)
  
  try {
    // Exchange code for token with MCP server
    const tokenInfos =  {
          code,
        code_verifier: codeVerifier,
        client_id: clientId,
        grant_type: 'authorization_code'
      }

    const formData = new URLSearchParams()

    Object.entries(tokenInfos).map(([key, value]) => {
      formData.append(key, value)
    })


    const tokenResponse = await fetch(`${config.mcpServerUrl}/token`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: formData.toString()
    });
    
    if (!tokenResponse.ok) {
      console.log(tokenResponse)
      throw new Error(`Token exchange failed: ${tokenResponse.statusText}`);
    }

    const session = {}    
    const tokenData = await tokenResponse.json();

    console.log("access token", tokenData.access_token)

    // Store token in session
    sessions.set(sessionId, {
      id: sessionId,
      accessToken: tokenData.access_token,
      refreshToken: tokenData.refresh_token,
      tokenExpires: Date.now() + tokenData.expires_in * 1000,
    })

    console.log("Sessions in oauth callback after set", [...sessions.entries()])

    return c.redirect('/');
  } catch (error) {
    console.log(error)
    return c.redirect(`/?error=${encodeURIComponent(error.message)}`);
  }
});

export default app;
