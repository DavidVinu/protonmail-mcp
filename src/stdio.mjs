#!/usr/bin/env node
// Proton Mail for MCP clients that launch the server as a child process.
//
// This is the entry point for Claude Code, Claude Desktop and anything else
// that speaks MCP over stdio. It is bound to the machine it runs on: the
// client starts the process, so there is nothing to expose and nothing to
// authenticate. For a server reachable over the network, see http.mjs.
//
// Register it with:
//   claude mcp add protonmail --scope user -- /path/to/src/stdio.mjs
//
// Note for Claude Code specifically: the configuration lives in ~/.claude.json,
// NOT in claude_desktop_config.json. An entry in the desktop configuration is
// not read by the CLI; the log then says "no stdio servers connected".

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { register, resolveConfig } from './tools.mjs';

const server = new McpServer({ name: 'protonmail', version: '1.0.0' });
register(server, resolveConfig());

await server.connect(new StdioServerTransport());
