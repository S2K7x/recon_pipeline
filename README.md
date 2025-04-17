# Recon Pipeline

## Overview

Recon Pipeline V5 is a Python-based tool designed to automate various reconnaissance tasks for a given target domain or list of domains. It integrates several popular open-source security tools to perform subdomain enumeration, DNS resolution, live host probing, JavaScript file discovery, directory/file fuzzing, historical URL gathering, parameter discovery, and vulnerability scanning.

The pipeline is designed to be modular and configurable, allowing users to enable/disable specific tools, customize tool options, and manage state between runs (e.g., tracking known subdomains).

## Features

* **Modular Tool Integration:** Wraps and orchestrates the execution of the following tools:
    * `subfinder`: Passive subdomain discovery.
    * `dnsx`: DNS resolution (A, AAAA records).
    * `httpx`: Probes subdomains to find live web servers.
    * `subjs`: Discovers JavaScript files hosted on live web servers.
    * `ffuf`: Fuzzes for directories and files on live web servers.
    * `gau`: Fetches known URLs from Wayback Machine, Common Crawl, and OTX.
    * `paramspider`: Discovers parameters from URLs.
    * `nuclei`: Scans discovered URLs for known vulnerabilities using configurable templates.
* **State Management:** Remembers previously found subdomains for a target to identify and report only *new* findings in subsequent runs. Directory findings are also compared against previous runs for specific hosts.
* **Configuration:** Uses a YAML file (`config.yaml`) for setting tool paths, default options, API keys (if needed by tools), and enabling/disabling modules.
* **Command-Line Control:** Offers extensive command-line arguments to override configuration settings, specify targets, control verbosity, and skip specific tools for a run.
* **Concurrency:** Leverages threading for concurrent directory checks (`ffuf`) and other tool executions where applicable (e.g., `dnsx`, `subjs`, `nuclei`).
* **Flexible Input:** Accepts a single domain or a file containing a list of domains.
* **Organized Output:** Stores results in a structured directory hierarchy based on the target domain, including logs of new findings and raw tool outputs (e.g., Nuclei JSONL, ParamSpider results).

## Requirements

* Python 3.x
* PyYAML (`pip install pyyaml`)
* The individual reconnaissance tools installed and available in your system's PATH or specified in `config.yaml`:
    * subfinder
    * dnsx
    * httpx
    * subjs
    * ffuf
    * gau
    * paramspider
    * nuclei

## Installation

1.  **Clone the repository (or place the script):**
    ```bash
    # If this were a git repo:
    # git clone (https://github.com/S2K7x/recon_pipeline)
    # cd recon_pipeline
    # Otherwise, just ensure recon_pipeline.py is present.
    ```
2.  **Install Python dependencies:**
    ```bash
    pip install pyyaml ##
    ```
3.  **Install required reconnaissance tools:** Follow the installation instructions for each tool listed in the [Requirements](#requirements) section. Ensure they are in your PATH or update their paths in the `config.yaml` file.
4.  **Prepare Configuration:** Copy or create a `config.yaml` file (see [Configuration](#configuration)). You may need to download or specify a wordlist (e.g., `common_dirs.txt`).

## Configuration

The pipeline uses a `config.yaml` file to manage settings. A default configuration is provided (`config.yaml`).

Key sections in `config.yaml`:

* **`paths`**: Specify the full path to each tool's executable if they are not in your system's PATH. Also define the path to the wordlist used by `ffuf` and the base output directory.
* **`settings`**: Define global settings like the User-Agent, default ports for `httpx`, default paths for `ffuf` checks, and default concurrency for directory checks.
* **`tool_options`**: Configure individual tools:
    * `enabled`: Set to `true` or `false` to include/exclude a tool from the pipeline.
    * Tool-specific parameters (e.g., `threads`, `rate`, `severity`, `timeout`, `extra_flags`) can be set here.

Configuration values can be overridden by command-line arguments.

## Usage

```bash
./recon_pipeline.py [options] <domain> ##
# or
./recon_pipeline.py [options] -l <domain_list_file> ##
