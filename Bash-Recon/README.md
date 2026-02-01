# Bash-Recon: Passive Subdomain Enumeration Tool

A simple Bash script for passive subdomain enumeration using Subfinder and crt.sh, followed by live host probing and detailed scanning with httpx. Designed for ease of use in reconnaissance workflows.

## Features

- **Passive Enumeration**: Gathers subdomains from Subfinder and crt.sh without active scanning.
- **Live Host Detection**: Uses httpx to identify responsive hosts.
- **Detailed Scans**: Extracts titles, status codes, technologies, content length, and web servers.
- **Multi-Domain Support**: Handle single domains or lists of domains.
- **Customizable**: Specify output directory and thread count for httpx.
- **Sanitization**: Automatically cleans input domains (removes protocols, paths, ports).
- **Output Organization**: Combined results plus per-domain breakdowns for multi-domain runs.
- **Colorized Output**: Easy-to-read console feedback with status indicators.

## Dependencies

This script requires the following tools to be installed:

- [Subfinder](https://github.com/projectdiscovery/subfinder) (for subdomain enumeration)
- [httpx](https://github.com/projectdiscovery/httpx) (for live host probing)
- `curl` (for fetching crt.sh data)
- `jq` (for parsing JSON from crt.sh)

Install them via your package manager (e.g., `apt install curl jq`) or follow the GitHub instructions for Subfinder and httpx from ProjectDiscovery.

## Installation

1. Clone the repository:

`git clone https://github.com/9mmPterodactyl/My-Tools.git`
 
`cd My-Tools/Bash-Recon `

2. Make the script executable:

`chmod +x bash-recon.sh`


3. Ensure dependencies are installed and in your PATH.

## Usage

`./bash-recon.sh -u <domain> | -l <domain_list> [-o <output_dir>] [-t <threads>]`

### Options

- `-u <domain>`: Single domain to enumerate (e.g., example.com).
- `-l <domain_list>`: File containing a list of domains (one per line).
- `-o <output_dir>`: Custom output directory name (default: `recon_<target>_<date>`).
- `-t <threads>`: Number of threads for httpx (default: 50).

Note: You cannot use `-u` and `-l` together.

### Examples

- Single domain:

`./bash-recon.sh -u example.com`

- Domain list:

`./bash-recon.sh -l domains.txt -o my_results -t 100`

## Output

Results are saved in the specified output directory:

- `all_subdomains.txt`: Combined unique list of all subdomains.
- `live_hosts.txt`: List of live URLs (http/https).
- `live_hosts_detailed.txt`: Detailed info including title, status code, tech stack, content length, and web server.
- `by_domain/` (for multi-domain runs): Per-domain subdomains and live hosts.

Console output includes a summary of targets scanned, unique subdomains, and live hosts.


