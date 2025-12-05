# Kali-mcp

**Kali-mcp** is a simple Model Context Protocol (MCP) server implementation by “esa” that lets you expose a Linux (e.g. Kali) shell as an MCP-accessible API. This enables MCP-clients (like AI assistants or automation tools) to invoke shell commands on a remote (or local) Kali machine via structured API calls.

## 📦 What’s inside

- `server.py` — The MCP / API server code  
- `requirements.txt` — Python dependencies  
- `Dockerfile.txt` — (Optional) Docker setup instructions  
- `claude_desktop_config.json` — Example config for setting up with an MCP-client (e.g. Claude Desktop)  
- `.gitignore.txt` — Basic ignore file  

## ✅ Features & Use Cases

- Expose any shell commands or installed Kali tools (e.g. `nmap`, `curl`, `gobuster`, etc.) via MCP.  
- Allow AI-clients or automation scripts to run penetration-testing / reconnaissance / CTF commands via a standard protocol.  
- Easy to integrate with AI-powered tools that support MCP, enabling automated workflows.  
- Option to containerize (with Docker) for isolation and portability.  

## 🚀 Getting Started

### Prerequisites

- A Linux machine (ideally Kali Linux) — or any Linux with desired tools installed.  
- Python 3.8+ (or matching the version used in `server.py`)  
- (Optional) Docker, if you want to run the server in a container.  

### Installation (host/server side)

```bash
git clone https://github.com/HrskiEsa/Kali-mcp.git
cd Kali-mcp
pip install -r requirements.txt
python3 server.py
