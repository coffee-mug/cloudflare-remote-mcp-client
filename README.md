# MCP Remote Client deployable on Cloudflare
Tested with Cloudflare Remote MCP Server.

Rationale: build MCP client you can host on Cloudflare and make visible to your users. Use case: embed MCP capabilities in your
SaaS, ...


## Create Remote Server

Create one in another directory
```
> npm create cloudflare@latest -- my-mcp-server --template=cloudflare/ai/demos/remote-mcp-server
```

## Start Remote Client
```
> npm run dev
```

## Start Remote Server
```
> npm run dev
```

Go to [http://localhost:4000](localhost:4000) to see it in action
