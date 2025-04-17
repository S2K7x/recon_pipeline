#!/usr/bin/env python3

import os
import sys
import subprocess
import argparse
from datetime import datetime
import tempfile
import shlex
import logging
from urllib.parse import urlparse
import yaml # Requires PyYAML: pip install pyyaml
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
import json # For parsing Nuclei JSONL output

# --- Global Variables ---
CONFIG = {}
BASE_RESULTS_DIR = "recon_results"

# --- Logging Setup ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

# --- Configuration Handling ---

def load_config(config_path):
    """Loads configuration from a YAML file."""
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            return yaml.safe_load(f)
    except FileNotFoundError:
        logging.warning(f"Config file not found at {config_path}. Using defaults.")
        return {}
    except Exception as e:
        logging.error(f"Error loading config file {config_path}: {e}")
        return {}

def merge_configs(args):
    """Merges default config, file config, and CLI args, including skip flags."""
    global CONFIG, BASE_RESULTS_DIR

    # 1. Start with script defaults including 'enabled' flags
    conf = {
        'paths': {'subfinder': None, 'httpx': None, 'ffuf': None, 'gau': None, 'nuclei': None, 'dnsx': None, 'subjs': None, 'paramspider': None, 'wordlist': 'common_dirs.txt', 'output_base_dir': 'recon_results'},
        'settings': {'user_agent': 'PythonReconPipeline/5.0', 'default_ports': '80,443', 'default_check_paths': ['/'], 'default_threads': 10},
        'tool_options': {
            'subfinder': {'enabled': True, 'extra_flags': '-passive'},
            'dnsx': {'enabled': True, 'threads': 50, 'extra_flags': '-resp -a -aaaa'}, # Added DNSX
            'httpx': {'enabled': True, 'timeout': 10, 'extra_flags': ''},
            'subjs': {'enabled': True, 'concurrency': 20, 'extra_flags': ''}, # Added SubJS
            'ffuf': {'enabled': True, 'threads': 20, 'rate': 0, 'match_codes': '200,204,301,302,307,403', 'filter_size': '0', 'extra_flags': ''},
            'gau': {'enabled': True, 'threads': 5, 'extra_flags': '--subs --providers wayback,commoncrawl,otx'},
            'paramspider': {'enabled': True, 'extra_flags': '--exclude woff,css,js,png,svg,jpg,ttf,otf'}, # Added ParamSpider
            'nuclei': {'enabled': True, 'templates': '', 'severity': 'high,critical', 'concurrency': 10, 'rate_limit': 150, 'extra_flags': ''}
        }
    }

    # 2. Load config file
    file_config = {}
    if args.config and os.path.exists(args.config):
        file_config = load_config(args.config)
    elif args.config:
         logging.warning(f"Specified config file '{args.config}' not found. Ignoring.")

    # 3. Deep merge file config into defaults
    for key, value in file_config.items():
        if key in conf and isinstance(conf[key], dict) and isinstance(value, dict):
            for sub_key, sub_value in value.items():
                 if key == 'tool_options' and sub_key not in conf[key]: conf[key][sub_key] = {}
                 if isinstance(conf[key].get(sub_key), dict) and isinstance(sub_value, dict):
                      conf[key][sub_key].update(sub_value)
                 else:
                      conf[key][sub_key] = sub_value
        else:
            conf[key] = value

    # 4. Override with CLI arguments
    # Paths & Settings
    if args.wordlist: conf['paths']['wordlist'] = args.wordlist
    if args.output_dir: conf['paths']['output_base_dir'] = args.output_dir
    BASE_RESULTS_DIR = conf['paths']['output_base_dir']
    if args.ports: conf['settings']['default_ports'] = args.ports
    if args.threads is not None: conf['settings']['default_threads'] = args.threads
    if args.check_paths: conf['settings']['default_check_paths'] = [p.strip() for p in args.check_paths.split(',')]

    # Tool Options Specific Args
    if args.dnsx_threads is not None: conf['tool_options']['dnsx']['threads'] = args.dnsx_threads # Added
    if args.ffuf_threads is not None: conf['tool_options']['ffuf']['threads'] = args.ffuf_threads
    if args.ffuf_rate is not None: conf['tool_options']['ffuf']['rate'] = args.ffuf_rate
    if args.ffuf_mc: conf['tool_options']['ffuf']['match_codes'] = args.ffuf_mc
    if args.ffuf_fs: conf['tool_options']['ffuf']['filter_size'] = args.ffuf_fs
    if args.gau_threads is not None: conf['tool_options']['gau']['threads'] = args.gau_threads
    if args.subjs_concurrency is not None: conf['tool_options']['subjs']['concurrency'] = args.subjs_concurrency # Added
    if args.nuclei_severity: conf['tool_options']['nuclei']['severity'] = args.nuclei_severity
    if args.nuclei_templates: conf['tool_options']['nuclei']['templates'] = args.nuclei_templates
    if args.nuclei_concurrency is not None: conf['tool_options']['nuclei']['concurrency'] = args.nuclei_concurrency
    if args.nuclei_rate_limit is not None: conf['tool_options']['nuclei']['rate_limit'] = args.nuclei_rate_limit

    # Append Raw Extra Flags from CLI (Ensure keys exist)
    for tool in ['subfinder', 'dnsx', 'httpx', 'subjs', 'ffuf', 'gau', 'paramspider', 'nuclei']:
        conf['tool_options'].setdefault(tool, {}).setdefault('extra_flags', '')
        cli_arg_name = f"{tool}_flags"
        if hasattr(args, cli_arg_name) and getattr(args, cli_arg_name):
            conf['tool_options'][tool]['extra_flags'] += f" {getattr(args, cli_arg_name)}"

    # 5. Apply CLI Skip Flags
    if args.skip_subfinder: conf['tool_options']['subfinder']['enabled'] = False
    if args.skip_dnsx: conf['tool_options']['dnsx']['enabled'] = False # Added
    if args.skip_httpx: conf['tool_options']['httpx']['enabled'] = False
    if args.skip_subjs: conf['tool_options']['subjs']['enabled'] = False # Added
    if args.skip_ffuf: conf['tool_options']['ffuf']['enabled'] = False
    if args.skip_gau: conf['tool_options']['gau']['enabled'] = False
    if args.skip_paramspider: conf['tool_options']['paramspider']['enabled'] = False # Added
    if args.skip_nuclei: conf['tool_options']['nuclei']['enabled'] = False

    CONFIG = conf

    # Validate essential config
    if CONFIG.get('tool_options', {}).get('ffuf', {}).get('enabled', False) and not os.path.exists(CONFIG['paths']['wordlist']):
        logging.error(f"FFUF is enabled but Wordlist file not found: {CONFIG['paths']['wordlist']}")
        sys.exit(1)


# --- Helper Functions (State Management - unchanged) ---
def load_set_from_file(filepath):
    if not os.path.exists(filepath): return set()
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            return {line.strip() for line in f if line.strip()}
    except Exception as e:
        logging.error(f"Error reading file {filepath}: {e}")
        return set()

def save_set_to_file(filepath, data_set):
    try:
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        str_data_set = {str(item) for item in data_set}
        with open(filepath, 'w', encoding='utf-8') as f:
            for item in sorted(list(str_data_set)):
                f.write(f"{item}\n")
    except Exception as e:
        logging.error(f"Error writing to file {filepath}: {e}")

# --- Modular Tool Execution Functions ---
def run_command(command_str, tool_name="command"):
    # (Identical to previous version)
    logging.debug(f"Preparing {tool_name} command: {command_str}")
    try: parts = shlex.split(command_str)
    except ValueError as e:
        logging.error(f"Error splitting command string for {tool_name}: {command_str} - Error: {e}")
        return None
    executable_name = parts[0]
    tool_path_cfg = CONFIG.get('paths', {}).get(tool_name)
    if tool_path_cfg and os.path.sep not in executable_name:
        parts[0] = tool_path_cfg
        logging.debug(f"Using configured path for {tool_name}: {tool_path_cfg}")
    final_command_parts = [str(p) for p in parts]
    final_command_str_log = ' '.join(shlex.quote(p) for p in final_command_parts)
    logging.debug(f"Executing {tool_name}: {final_command_str_log}")
    try:
        process = subprocess.run(
            final_command_parts, capture_output=True, text=True, check=False,
            encoding='utf-8', errors='ignore'
        )
        if process.returncode != 0:
            stderr_output = process.stderr.strip()
            logging.error(f"{tool_name} failed (code {process.returncode}): {final_command_str_log}")
            if stderr_output: logging.error(f"Stderr: {stderr_output}")
            return None
        return [line.strip() for line in process.stdout.strip().split('\n') if line.strip()]
    except FileNotFoundError:
        logging.error(f"Error: {tool_name} executable ('{final_command_parts[0]}') not found. Check config path or system PATH.")
        return None
    except Exception as e:
        logging.error(f"Unexpected error running {tool_name} '{final_command_str_log}': {e}", exc_info=True)
        return None

# --- Tool Specific Runners ---

def run_subfinder(target_domain):
    # (Unchanged)
    logging.info(f"Running subfinder for {target_domain}...")
    extra_flags = CONFIG.get('tool_options', {}).get('subfinder', {}).get('extra_flags', '')
    command_str = f"subfinder -d {shlex.quote(target_domain)} -silent {extra_flags}"
    results = run_command(command_str, tool_name="subfinder")
    if results is None: return None
    logging.info(f"Subfinder found {len(results)} potential subdomains.")
    return set(results)

def run_dnsx(subdomains_set):
    """Runs dnsx to resolve subdomains."""
    if not subdomains_set: return {} # Return empty dict if no input
    logging.info(f"Running DNSX resolution for {len(subdomains_set)} subdomains...")
    resolved_map = {} # Store as {subdomain: [ip1, ip2]}
    opts = CONFIG.get('tool_options', {}).get('dnsx', {})
    threads = opts.get('threads', 50)
    extra_flags = opts.get('extra_flags', '-resp -a -aaaa') # Default flags

    with tempfile.NamedTemporaryFile(mode='w', delete=False, encoding='utf-8') as tmp_file:
        for subdomain in subdomains_set: tmp_file.write(f"{subdomain}\n")
        tmp_filepath = tmp_file.name

    try:
        command_parts = ["dnsx", "-l", tmp_filepath, "-silent", "-t", str(threads)]
        if extra_flags: command_parts.extend(shlex.split(extra_flags))
        command_str = ' '.join(command_parts)

        results = run_command(command_str, tool_name="dnsx")

        if results:
            # Example parsing for '-resp' format: domain,[ip]
            for line in results:
                parts = line.split(',')
                if len(parts) == 2:
                    domain = parts[0].strip()
                    ip = parts[1].strip().strip('[]') # Remove brackets if present
                    if domain not in resolved_map:
                        resolved_map[domain] = []
                    if ip: # Ensure IP is not empty
                         resolved_map[domain].append(ip)
            logging.info(f"DNSX resolved {len(resolved_map)} subdomains to IPs.")
        else:
            logging.info("DNSX found no resolutions (or failed).")

    finally:
        if os.path.exists(tmp_filepath):
            try: os.remove(tmp_filepath)
            except OSError as e: logging.warning(f"Could not remove temporary file {tmp_filepath}: {e}")

    return resolved_map

def run_httpx(subdomains_set):
    # (Unchanged)
    if not subdomains_set: return []
    logging.info(f"Running httpx on {len(subdomains_set)} subdomains...")
    # ... (rest of httpx function is the same) ...
    with tempfile.NamedTemporaryFile(mode='w', delete=False, encoding='utf-8') as tmp_file:
        for subdomain in subdomains_set: tmp_file.write(f"{subdomain}\n")
        tmp_filepath = tmp_file.name
    live_urls = []
    try:
        ports = CONFIG.get('settings', {}).get('default_ports', '80,443')
        timeout = CONFIG.get('tool_options', {}).get('httpx', {}).get('timeout', 10)
        user_agent = CONFIG.get('settings', {}).get('user_agent', 'PythonReconPipeline')
        extra_flags = CONFIG.get('tool_options', {}).get('httpx', {}).get('extra_flags', '')
        command_str = (
            f"httpx -l {shlex.quote(tmp_filepath)} -silent -no-color "
            f"-ports {shlex.quote(ports)} -timeout {timeout} "
            f"-H \"User-Agent: {user_agent}\" {extra_flags}"
        )
        results = run_command(command_str, tool_name="httpx")
        if results:
            live_urls = results
            logging.info(f"Httpx found {len(live_urls)} live URLs.")
        else:
             logging.info("Httpx found no live URLs.")
    finally:
        if os.path.exists(tmp_filepath):
            try: os.remove(tmp_filepath)
            except OSError as e: logging.warning(f"Could not remove temporary file {tmp_filepath}: {e}")
    return live_urls

def run_subjs(urls_list):
    """Runs subjs to find JavaScript file URLs."""
    if not urls_list: return set()
    logging.info(f"Running SubJS on {len(urls_list)} URLs...")
    js_urls = set()
    opts = CONFIG.get('tool_options', {}).get('subjs', {})
    concurrency = opts.get('concurrency', 20)
    extra_flags = opts.get('extra_flags', '')

    with tempfile.NamedTemporaryFile(mode='w', delete=False, encoding='utf-8') as tmp_file:
        for url in urls_list: tmp_file.write(f"{url}\n")
        tmp_filepath = tmp_file.name

    try:
        command_parts = ["subjs", "-i", tmp_filepath, "-c", str(concurrency)]
        if extra_flags: command_parts.extend(shlex.split(extra_flags))
        command_str = ' '.join(command_parts)

        results = run_command(command_str, tool_name="subjs")

        if results:
            js_urls = set(results) # subjs output is one URL per line
            logging.info(f"SubJS found {len(js_urls)} JavaScript URLs.")
        else:
            logging.info("SubJS found no JavaScript URLs (or failed).")

    finally:
        if os.path.exists(tmp_filepath):
            try: os.remove(tmp_filepath)
            except OSError as e: logging.warning(f"Could not remove temporary file {tmp_filepath}: {e}")

    return js_urls


def run_ffuf(base_url, path, wordlist):
    # (Unchanged)
    logging.debug(f"Running ffuf on {base_url}{path} ...")
    # ... (rest of ffuf function is the same) ...
    if not os.path.exists(wordlist):
        logging.error(f"Wordlist not found for ffuf: {wordlist}")
        return set()
    opts = CONFIG.get('tool_options', {}).get('ffuf', {})
    threads = opts.get('threads', 20)
    rate = opts.get('rate', 0)
    mc = opts.get('match_codes', '200,204,301,302,307,403')
    fs = opts.get('filter_size', '0')
    user_agent = CONFIG.get('settings', {}).get('user_agent', 'PythonReconPipeline')
    extra_flags = opts.get('extra_flags', '')
    if not path.startswith('/'): path = '/' + path
    target_url = f"{base_url.rstrip('/')}{path.rstrip('/')}/FUZZ"
    command_str = (
        f"ffuf -u {shlex.quote(target_url)} -w {shlex.quote(wordlist)} "
        f"-t {threads} " + (f"-rate {rate} " if rate > 0 else "") +
        f"-mc {shlex.quote(mc)} -fs {shlex.quote(fs)} -silent "
        f"-H \"User-Agent: {user_agent}\" {extra_flags}"
    )
    results = run_command(command_str, tool_name="ffuf")
    if results is None: return set()
    found_paths = set()
    for line in results:
         if line and not line.startswith("::"):
            full_found_path = os.path.join(path, line.strip()).replace('\\', '/')
            if not full_found_path.startswith('/'): full_found_path = '/' + full_found_path
            found_paths.add(full_found_path)
    logging.debug(f"ffuf on {base_url}{path} found {len(found_paths)} items relative to root.")
    return found_paths


def run_gau(subdomains_set):
    # (Unchanged)
    if not subdomains_set: return set()
    logging.info(f"Running GAU for {len(subdomains_set)} subdomains...")
    # ... (rest of gau function is the same) ...
    urls_found = set()
    opts = CONFIG.get('tool_options', {}).get('gau', {})
    threads = opts.get('threads', 5)
    extra_flags = opts.get('extra_flags', '')
    with tempfile.NamedTemporaryFile(mode='w', delete=False, encoding='utf-8') as tmp_file:
        for subdomain in subdomains_set: tmp_file.write(f"{subdomain}\n")
        tmp_filepath = tmp_file.name
    try:
        cat_command = ["cat", tmp_filepath]
        gau_command_parts = ["gau", "--threads", str(threads)]
        if extra_flags: gau_command_parts.extend(shlex.split(extra_flags))
        logging.debug(f"Executing GAU pipeline: cat {tmp_filepath} | {' '.join(shlex.quote(p) for p in gau_command_parts)}")
        cat_proc = subprocess.Popen(cat_command, stdout=subprocess.PIPE, text=True, encoding='utf-8', errors='ignore')
        gau_proc = subprocess.Popen(gau_command_parts, stdin=cat_proc.stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding='utf-8', errors='ignore')
        cat_proc.stdout.close()
        stdout, stderr = gau_proc.communicate()
        if gau_proc.returncode != 0:
            logging.error(f"GAU failed (code {gau_proc.returncode}).")
            if stderr: logging.error(f"GAU Stderr: {stderr.strip()}")
        else:
            urls_found = {line.strip() for line in stdout.strip().split('\n') if line.strip()}
            logging.info(f"GAU found {len(urls_found)} historical URLs.")
        if stderr and gau_proc.returncode == 0:
             logging.debug(f"GAU Stderr output: {stderr.strip()}")
    except FileNotFoundError:
        logging.error("Error: 'gau' or 'cat' command not found. Check installation and PATH.")
    except Exception as e:
        logging.error(f"An unexpected error occurred running GAU: {e}", exc_info=True)
    finally:
        if os.path.exists(tmp_filepath):
            try: os.remove(tmp_filepath)
            except OSError as e: logging.warning(f"Could not remove temporary file {tmp_filepath}: {e}")
    return urls_found

def run_paramspider(urls_set, target_domain, timestamp):
    """Runs ParamSpider on a set of URLs."""
    if not urls_set: return None # Return None if no input
    logging.info(f"Running ParamSpider on {len(urls_set)} URLs...")
    opts = CONFIG.get('tool_options', {}).get('paramspider', {})
    extra_flags = opts.get('extra_flags', '')
    target_results_dir = os.path.join(BASE_RESULTS_DIR, target_domain)
    # Define a specific output directory for paramspider within the target results
    param_output_dir = os.path.join(target_results_dir, f"paramspider_output_{timestamp}")

    with tempfile.NamedTemporaryFile(mode='w', delete=False, encoding='utf-8') as tmp_file:
        # Paramspider might prefer domain input, let's try with URL list first
        # It might internally extract domains. If not, we might need to pass domains instead.
        for url in urls_set:
             # Basic check to only include http/https URLs
             if url.startswith("http://") or url.startswith("https://"):
                  tmp_file.write(f"{url}\n")
        tmp_filepath = tmp_file.name

    output_location = None
    try:
        # Ensure output directory exists
        os.makedirs(param_output_dir, exist_ok=True)

        command_parts = ["paramspider", "-l", tmp_filepath, "--output", param_output_dir]
        if extra_flags: command_parts.extend(shlex.split(extra_flags))
        command_str = ' '.join(command_parts)

        # Run paramspider - it outputs to files, so we don't capture stdout
        run_command(command_str, tool_name="paramspider")

        # Check if output directory contains results (basic check)
        if os.path.exists(param_output_dir) and len(os.listdir(param_output_dir)) > 0:
            logging.info(f"ParamSpider finished. Results saved in: {param_output_dir}")
            output_location = param_output_dir # Return path if successful
        else:
            logging.warning(f"ParamSpider ran but output directory '{param_output_dir}' is empty or missing.")
            # Clean up empty dir? Optional.
            # try: os.rmdir(param_output_dir)
            # except OSError: pass


    except Exception as e:
        logging.error(f"An unexpected error occurred running ParamSpider: {e}", exc_info=True)
    finally:
        if os.path.exists(tmp_filepath):
            try: os.remove(tmp_filepath)
            except OSError as e: logging.warning(f"Could not remove temporary file {tmp_filepath}: {e}")

    return output_location # Return the output dir path or None


def run_nuclei(urls_to_scan, target_domain, timestamp):
    # (Unchanged)
    if not urls_to_scan: return []
    logging.info(f"Running Nuclei scan on {len(urls_to_scan)} URLs...")
    # ... (rest of nuclei function is the same) ...
    findings = []
    opts = CONFIG.get('tool_options', {}).get('nuclei', {})
    templates = opts.get('templates', '')
    severity = opts.get('severity', 'high,critical')
    concurrency = opts.get('concurrency', 10)
    rate_limit = opts.get('rate_limit', 150)
    extra_flags = opts.get('extra_flags', '')
    user_agent = CONFIG.get('settings', {}).get('user_agent', 'PythonReconPipeline')
    target_results_dir = os.path.join(BASE_RESULTS_DIR, target_domain)
    nuclei_output_jsonl = os.path.join(target_results_dir, f"nuclei_findings_{timestamp}.jsonl")
    with tempfile.NamedTemporaryFile(mode='w', delete=False, encoding='utf-8') as tmp_file:
        for url in urls_to_scan: tmp_file.write(f"{url}\n")
        tmp_filepath = tmp_file.name
    try:
        command_parts = [
            "nuclei", "-l", tmp_filepath, "-silent", "-jsonl",
            "-o", nuclei_output_jsonl,
            "-c", str(concurrency),
            "-rl", str(rate_limit),
            "-H", f"User-Agent: {user_agent}"
        ]
        if severity: command_parts.extend(["-s", severity])
        if templates: command_parts.extend(["-t", templates])
        if extra_flags: command_parts.extend(shlex.split(extra_flags))
        command_str = ' '.join(command_parts)
        run_command(command_str, tool_name="nuclei") # Ignore stdout
        if os.path.exists(nuclei_output_jsonl):
            logging.info(f"Processing Nuclei results from: {nuclei_output_jsonl}")
            with open(nuclei_output_jsonl, 'r', encoding='utf-8') as f:
                for line in f:
                    try:
                        result = json.loads(line.strip())
                        template_id = result.get("template-id", "N/A")
                        name = result.get("info", {}).get("name", "N/A")
                        sev = result.get("info", {}).get("severity", "N/A").upper()
                        host = result.get("host", "N/A")
                        matched = result.get("matched-at", host)
                        curl_command = result.get("curl-command", None)
                        finding_str = f"NUCLEI:[{sev}] {name} ({template_id}) found at {matched}"
                        print(f"[!] {finding_str}")
                        findings.append(finding_str)
                        if curl_command and logging.getLogger().level == logging.DEBUG:
                             logging.debug(f"  Curl command: {curl_command}")
                    except json.JSONDecodeError:
                        logging.warning(f"Skipping invalid JSON line in Nuclei output: {line.strip()}")
                    except Exception as e:
                        logging.error(f"Error parsing Nuclei result line: {e}", exc_info=True)
            logging.info(f"Nuclei scan finished. Found {len(findings)} issues matching severity filter.")
        else:
            logging.warning("Nuclei command ran but output file was not found.")
    except Exception as e:
         logging.error(f"An error occurred during Nuclei execution setup: {e}", exc_info=True)
    finally:
        if os.path.exists(tmp_filepath):
            try: os.remove(tmp_filepath)
            except OSError as e: logging.warning(f"Could not remove temporary file {tmp_filepath}: {e}")
    return findings


# --- Concurrency Handler for Directory Checks (unchanged) ---
def process_single_url_dirs(target_domain, live_url):
    # (Identical to previous version)
    new_findings_for_url = []
    all_found_dirs_for_url = set()
    check_paths = CONFIG.get('settings', {}).get('default_check_paths', ['/'])
    wordlist = CONFIG.get('paths', {}).get('wordlist')
    target_results_dir = os.path.join(BASE_RESULTS_DIR, target_domain)
    logging.debug(f"Processing URL for directory checks: {live_url}")
    try:
        parsed_url = urlparse(live_url)
        host_for_file = parsed_url.netloc.replace('.', '_').replace(':','_port_')
        known_dirs_file = os.path.join(target_results_dir, f"known_dirs_{host_for_file}.txt")
        known_dirs_set = load_set_from_file(known_dirs_file)
        logging.debug(f"Loaded {len(known_dirs_set)} known directories for {live_url}")
        for check_path in check_paths:
            if not check_path.startswith('/'): check_path = '/' + check_path
            found_in_path = run_ffuf(live_url, check_path, wordlist)
            all_found_dirs_for_url.update(found_in_path)
            time.sleep(0.05)
        new_dirs_set = all_found_dirs_for_url - known_dirs_set
        if new_dirs_set:
            logging.info(f"Found {len(new_dirs_set)} NEW items on {live_url}:")
            for directory_path in sorted(list(new_dirs_set)):
                found_item_url = f"{live_url.rstrip('/')}{directory_path}"
                print(f"[+] NEW DIR : {found_item_url}")
                new_findings_for_url.append(f"DIR: {found_item_url}")
        else:
            if logging.getLogger().level == logging.DEBUG or known_dirs_set:
                 logging.info(f"No new directories/files found on {live_url}")
        if all_found_dirs_for_url:
            save_set_to_file(known_dirs_file, all_found_dirs_for_url)
    except Exception as e:
         logging.error(f"Error processing directory check for {live_url}: {e}", exc_info=True)
    return new_findings_for_url

# --- Main Execution Logic ---

def process_target(target_domain):
    """Runs the full recon pipeline for a single target domain, respecting skip flags."""
    logging.info(f"--- Starting Recon Pipeline for: {target_domain} ---")
    target_results_dir = os.path.join(BASE_RESULTS_DIR, target_domain)
    os.makedirs(target_results_dir, exist_ok=True)
    known_subdomains_file = os.path.join(target_results_dir, "known_subdomains.txt")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    new_findings_log_file = os.path.join(target_results_dir, f"new_findings_{timestamp}.log")
    all_new_findings = []

    # --- Check if tools are enabled ---
    subfinder_enabled = CONFIG.get('tool_options', {}).get('subfinder', {}).get('enabled', False)
    dnsx_enabled = CONFIG.get('tool_options', {}).get('dnsx', {}).get('enabled', False) # Added
    gau_enabled = CONFIG.get('tool_options', {}).get('gau', {}).get('enabled', False)
    httpx_enabled = CONFIG.get('tool_options', {}).get('httpx', {}).get('enabled', False)
    subjs_enabled = CONFIG.get('tool_options', {}).get('subjs', {}).get('enabled', False) # Added
    paramspider_enabled = CONFIG.get('tool_options', {}).get('paramspider', {}).get('enabled', False) # Added
    ffuf_enabled = CONFIG.get('tool_options', {}).get('ffuf', {}).get('enabled', False)
    nuclei_enabled = CONFIG.get('tool_options', {}).get('nuclei', {}).get('enabled', False)

    # --- Data storage ---
    known_subdomains_set = set()
    current_subdomains_set = set()
    resolved_ips_map = {} # Store {domain: [ips]}
    gau_urls_set = set()
    live_new_urls = [] # URLs from httpx on new subs
    js_urls_set = set() # URLs found by subjs
    paramspider_output_location = None
    dir_check_findings = []
    nuclei_findings = []


    # --- 1. Load Previous Subdomain State ---
    known_subdomains_set = load_set_from_file(known_subdomains_file)
    logging.info(f"Loaded {len(known_subdomains_set)} previously known subdomains for {target_domain}.")

    # --- 2. Run Subdomain Enumeration ---
    subfinder_succeeded = False
    if subfinder_enabled:
        current_subdomains_set = run_subfinder(target_domain)
        if current_subdomains_set is None:
             logging.error(f"Subfinder failed for {target_domain}. Relying on previous data if available.")
             current_subdomains_set = known_subdomains_set
             subfinder_succeeded = False
        else:
             subfinder_succeeded = True
             if not current_subdomains_set and not known_subdomains_set:
                  logging.warning(f"Subfinder found no domains for {target_domain}, and no previous data exists. Limited run.")
    else:
        logging.info("Subfinder step skipped by configuration.")
        current_subdomains_set = known_subdomains_set

    if not current_subdomains_set:
         logging.warning(f"No subdomains available for {target_domain}. Ending processing.")
         return

    # --- 3. Identify and Report New Subdomains ---
    new_subdomains_set = current_subdomains_set - known_subdomains_set
    if subfinder_succeeded:
        if new_subdomains_set:
            logging.info(f"Found {len(new_subdomains_set)} NEW subdomains for {target_domain}:")
            sorted_new_subs = sorted(list(new_subdomains_set))
            for sub in sorted_new_subs:
                print(f"[+] NEW SUB : {sub}")
                all_new_findings.append(f"SUBDOMAIN: {sub}")
        else:
            logging.info(f"No new subdomains found for {target_domain} in this run.")
    elif new_subdomains_set:
         logging.info(f"Note: Subfinder skipped. {len(new_subdomains_set)} subdomains are present now that were not known before.")


    # --- 4. Run DNS Resolution ---
    if dnsx_enabled:
        if current_subdomains_set:
             resolved_ips_map = run_dnsx(current_subdomains_set)
             # Optionally log resolved IPs or save them
             # save_resolved_ips(resolved_ips_map, target_results_dir)
        else:
             logging.info("No subdomains available to resolve with DNSX.")
    else:
        logging.info("DNSX step skipped by configuration.")


    # --- 5. Run GAU ---
    if gau_enabled:
        if current_subdomains_set:
             gau_urls_set = run_gau(current_subdomains_set)
        else:
             logging.info("No subdomains available to fetch GAU URLs for.")
    else:
        logging.info("GAU step skipped by configuration.")

    # --- 6. Check New Subdomains for Live Web Servers ---
    if httpx_enabled:
        if new_subdomains_set:
            live_new_urls = run_httpx(new_subdomains_set)
        else:
            logging.info("No new subdomains found, skipping HTTPX check for new subs.")
    else:
        logging.info("HTTPX step skipped by configuration.")
        # Cannot run subjs or ffuf on new urls if httpx is skipped
        subjs_enabled = False
        ffuf_enabled = False # Re-evaluate ffuf_enabled based on httpx status

    # --- 7. Run SubJS (on new live URLs) ---
    if subjs_enabled:
        if live_new_urls:
            js_urls_set = run_subjs(live_new_urls)
            if js_urls_set:
                 logging.info(f"Found {len(js_urls_set)} JS URLs. Logging them.")
                 for js_url in sorted(list(js_urls_set)):
                      all_new_findings.append(f"JS_URL: {js_url}")
                 # Optionally save JS URLs to a file
                 # save_set_to_file(os.path.join(target_results_dir, f"js_urls_{timestamp}.txt"), js_urls_set)
            else:
                 logging.info("SubJS did not find any JS URLs.")
        else:
            logging.info("No new live URLs found (or HTTPX skipped), skipping SubJS.")
    else:
        logging.info("SubJS step skipped by configuration.")


    # --- 8. Run ParamSpider ---
    if paramspider_enabled:
        # Combine new live URLs and GAU URLs
        urls_for_params = set(live_new_urls) | gau_urls_set
        if urls_for_params:
            paramspider_output_location = run_paramspider(urls_for_params, target_domain, timestamp)
            if paramspider_output_location:
                 all_new_findings.append(f"PARAMSPIDER_RESULTS: See directory {paramspider_output_location}")
        else:
            logging.info("No URLs available from HTTPX/GAU for ParamSpider.")
    else:
        logging.info("ParamSpider step skipped by configuration.")


    # --- 9. Perform Directory Check on New Live Subdomains (Concurrent) ---
    if ffuf_enabled: # Check again as it might have been disabled if httpx was skipped
        if live_new_urls:
            logging.info(f"--- Starting Concurrent Directory Checks ({len(live_new_urls)} URLs) ---")
            max_workers = CONFIG.get('settings', {}).get('default_threads', 10)
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                future_to_url = {executor.submit(process_single_url_dirs, target_domain, url): url for url in live_new_urls}
                for future in as_completed(future_to_url):
                    url = future_to_url[future]
                    try:
                        results = future.result()
                        if results: dir_check_findings.extend(results)
                    except Exception as exc:
                        logging.error(f"URL {url} generated an exception during directory check: {exc}", exc_info=True)
            all_new_findings.extend(dir_check_findings)
            logging.info("--- Finished Concurrent Directory Checks ---")
        else:
             logging.info("No new live web URLs found to perform directory checks on.")
    else:
        # Log skip only if it wasn't already logged due to httpx skip
        if CONFIG.get('tool_options', {}).get('ffuf', {}).get('enabled', False):
             logging.info("FFUF step skipped by configuration.")


    # --- 10. Run Nuclei Scan ---
    if nuclei_enabled:
        urls_to_scan_with_nuclei = set()
        # Only include live_new_urls if httpx ran
        if CONFIG.get('tool_options', {}).get('httpx', {}).get('enabled', False):
            urls_to_scan_with_nuclei.update(live_new_urls)
        # Only include gau_urls if gau ran
        if CONFIG.get('tool_options', {}).get('gau', {}).get('enabled', False):
            urls_to_scan_with_nuclei.update(gau_urls_set)

        if urls_to_scan_with_nuclei:
            nuclei_findings = run_nuclei(urls_to_scan_with_nuclei, target_domain, timestamp)
            all_new_findings.extend(nuclei_findings)
        else:
            logging.info("No URLs found from enabled HTTPX/GAU steps to scan with Nuclei.")
    else:
        logging.info("Nuclei step skipped by configuration.")


    # --- 11. Update and Save Subdomain State ---
    if subfinder_enabled and subfinder_succeeded:
        logging.info(f"Saving current list of all found subdomains for {target_domain}...")
        save_set_to_file(known_subdomains_file, current_subdomains_set)
    elif not subfinder_enabled:
         logging.info("Subfinder was skipped, not updating known subdomains state file.")
    else:
         logging.warning("Subfinder failed, not updating known subdomains state file.")


    # --- 12. Save New Findings Log ---
    if all_new_findings:
        logging.info(f"Saving combined findings log for {target_domain} to: {new_findings_log_file}")
        save_set_to_file(new_findings_log_file, set(all_new_findings))
    else:
         logging.info(f"No new findings from enabled steps to log for {target_domain} in this run.")

    logging.info(f"--- Recon Pipeline Finished for: {target_domain} ---")


def main():
    # Setup Argument Parser
    parser = argparse.ArgumentParser(description="Recon pipeline V5 with DNS, JS, Params.",
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    # Input Options
    parser.add_argument("domain", nargs='?', help="Single target root domain (e.g., example.com). Required if -l is not used.")
    parser.add_argument("-l", "--list", help="File containing a list of target domains (one per line).")

    # Config & Output
    parser.add_argument("-c", "--config", default="config.yaml", help="Path to the YAML configuration file.")
    parser.add_argument("--output-dir", help="Override base directory for results specified in config.")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="Increase verbosity level (-v for DEBUG).")

    # Core Settings Overrides
    parser.add_argument("--wordlist", help="Override wordlist path specified in config.")
    parser.add_argument("--ports", help="Override ports for httpx scanning (comma-separated).")
    parser.add_argument("--threads", type=int, help="Override concurrency level for directory scanning.")
    parser.add_argument("--check-paths", help="Override paths to check with ffuf (comma-separated, e.g., '/,/api').")

    # --- Skip Flags ---
    parser.add_argument("--skip-subfinder", action="store_true", help="Skip the Subfinder step.")
    parser.add_argument("--skip-dnsx", action="store_true", help="Skip the DNSX resolution step.") # Added
    parser.add_argument("--skip-httpx", action="store_true", help="Skip the HTTPX probing step.")
    parser.add_argument("--skip-subjs", action="store_true", help="Skip the SubJS discovery step.") # Added
    parser.add_argument("--skip-ffuf", action="store_true", help="Skip the FFUF directory checking step.")
    parser.add_argument("--skip-gau", action="store_true", help="Skip the GAU historical URL fetching step.")
    parser.add_argument("--skip-paramspider", action="store_true", help="Skip the ParamSpider discovery step.") # Added
    parser.add_argument("--skip-nuclei", action="store_true", help="Skip the Nuclei scanning step.")


    # Tool Specific Overrides
    parser.add_argument("--dnsx-threads", type=int, help="Override dnsx thread count (-t).") # Added
    parser.add_argument("--ffuf-threads", type=int, help="Override ffuf internal thread count (-t).")
    parser.add_argument("--ffuf-rate", type=int, help="Override ffuf rate limit (-rate).")
    parser.add_argument("--ffuf-mc", help="Override ffuf match codes (-mc).")
    parser.add_argument("--ffuf-fs", help="Override ffuf filter size (-fs).")
    parser.add_argument("--gau-threads", type=int, help="Override GAU thread count.")
    parser.add_argument("--subjs-concurrency", type=int, help="Override SubJS concurrency (-c).") # Added
    parser.add_argument("--nuclei-severity", help="Override Nuclei severity filter (comma-separated).")
    parser.add_argument("--nuclei-templates", help="Override Nuclei templates (comma-separated paths/tags).")
    parser.add_argument("--nuclei-concurrency", type=int, help="Override Nuclei concurrency (-c).")
    parser.add_argument("--nuclei-rate-limit", type=int, help="Override Nuclei rate limit (-rl).")


    # Raw Flags (Use with caution)
    parser.add_argument("--subfinder-flags", help="Append extra raw flags to subfinder command.")
    parser.add_argument("--dnsx-flags", help="Append extra raw flags to dnsx command.") # Added
    parser.add_argument("--httpx-flags", help="Append extra raw flags to httpx command.")
    parser.add_argument("--subjs-flags", help="Append extra raw flags to subjs command.") # Added
    parser.add_argument("--ffuf-flags", help="Append extra raw flags to ffuf command.")
    parser.add_argument("--gau-flags", help="Append extra raw flags to gau command.")
    parser.add_argument("--paramspider-flags", help="Append extra raw flags to paramspider command.") # Added
    parser.add_argument("--nuclei-flags", help="Append extra raw flags to nuclei command.")


    args = parser.parse_args()

    # --- Set Logging Level ---
    if args.verbose >= 1: logging.getLogger().setLevel(logging.DEBUG)
    else: logging.getLogger().setLevel(logging.INFO)
    logging.debug("Debug logging enabled.") if args.verbose >= 1 else None

    # --- Load and Merge Config ---
    merge_configs(args)
    logging.debug(f"Final Configuration: {CONFIG}")

    # --- Determine Targets ---
    targets = []
    if args.list:
        if not os.path.exists(args.list):
            logging.error(f"Input target list file not found: {args.list}")
            sys.exit(1)
        try:
            with open(args.list, 'r', encoding='utf-8') as f:
                targets = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except Exception as e:
             logging.error(f"Error reading target list file {args.list}: {e}")
             sys.exit(1)
    elif args.domain:
        targets.append(args.domain)
    if not targets:
        logging.error("No target specified. Use a domain name or the -l/--list option with a valid file.")
        parser.print_help()
        sys.exit(1)

    logging.info(f"Processing {len(targets)} target domain(s)...")

    # --- Process Each Target ---
    overall_start_time = time.time()
    for target in targets:
        process_target(target.strip())

    overall_end_time = time.time()
    logging.info(f"--- Pipeline execution finished for all targets in {overall_end_time - overall_start_time:.2f} seconds ---")

if __name__ == "__main__":
    main()
