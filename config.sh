#!/bin/bash

# Script to install or update tools required for the Python Recon Pipeline

# --- Colors for Output ---
COLOR_RESET='\033[0m'
COLOR_GREEN='\033[0;32m'
COLOR_RED='\033[0;31m'
COLOR_YELLOW='\033[0;33m'
COLOR_BLUE='\033[0;34m'

# --- Helper Functions ---
print_info() {
  echo -e "${COLOR_BLUE}[*] $1${COLOR_RESET}"
}

print_success() {
  echo -e "${COLOR_GREEN}[+] $1${COLOR_RESET}"
}

print_warning() {
  echo -e "${COLOR_YELLOW}[!] $1${COLOR_RESET}"
}

print_error() {
  echo -e "${COLOR_RED}[-] $1${COLOR_RESET}"
}

# Function to check if a command exists
command_exists() {
  command -v "$1" >/dev/null 2>&1
}

# Function to check prerequisites
check_prerequisites() {
  print_info "Checking prerequisites..."
  local missing=0

  if ! command_exists go; then
    print_error "Go (golang) is not installed. Please install it first."
    missing=1
  else
     print_success "Go found: $(go version)"
  fi

  if ! command_exists python3; then
    print_error "Python 3 is not installed. Please install it first."
    missing=1
  else
     print_success "Python 3 found: $(python3 --version)"
  fi

   if ! command_exists pip3; then
    print_error "pip3 is not installed. Please install it (e.g., 'sudo apt install python3-pip' or 'brew install python3')."
    missing=1
  else
     print_success "pip3 found: $(pip3 --version | head -n 1)"
  fi

  if ! command_exists git; then
    print_error "Git is not installed. Please install it first."
    missing=1
  else
     print_success "Git found: $(git --version)"
  fi

  if [ $missing -ne 0 ]; then
    print_error "Please install the missing prerequisites and try again."
    exit 1
  fi

  # Check if GOPATH/bin or $HOME/go/bin is in PATH
  local go_bin_path=$(go env GOBIN)
  if [ -z "$go_bin_path" ]; then
      go_bin_path=$(go env GOPATH)/bin
      if [ ! -d "$go_bin_path" ]; then
          go_bin_path="$HOME/go/bin"
      fi
  fi

  if [[ ":$PATH:" != *":$go_bin_path:"* ]]; then
       print_warning "Your Go bin directory ('$go_bin_path') might not be in your PATH."
       print_warning "Please add 'export PATH=\$PATH:$go_bin_path' to your shell profile (.bashrc, .zshrc, etc.)"
  else
       print_success "Go bin directory ('$go_bin_path') seems to be in PATH."
  fi

  print_success "Prerequisites check passed."
}

# Function to install/update Go tools
install_go_tool() {
  local tool_name=$1
  local tool_path=$2
  print_info "Attempting to install/update $tool_name..."
  # Use GO111MODULE=on just in case, though it's default now
  if GO111MODULE=on go install -v "$tool_path@latest"; then
    print_success "$tool_name installed/updated successfully."
  else
    print_error "Failed to install/update $tool_name."
    # Optionally add specific error handling or retry logic here
  fi
}

# --- Main Installation Logic ---

check_prerequisites

print_info "Starting installation/update of Go-based tools..."

install_go_tool "subfinder" "github.com/projectdiscovery/subfinder/v2/cmd/subfinder"
install_go_tool "dnsx" "github.com/projectdiscovery/dnsx/cmd/dnsx"
install_go_tool "httpx" "github.com/projectdiscovery/httpx/cmd/httpx"
install_go_tool "nuclei" "github.com/projectdiscovery/nuclei/v3/cmd/nuclei"
install_go_tool "gau" "github.com/lc/gau/v2/cmd/gau"
install_go_tool "ffuf" "github.com/ffuf/ffuf/v2"
install_go_tool "subjs" "github.com/lc/subjs/v2/cmd/subjs"

print_info "Starting installation/update of Python-based tools and libraries..."

# Install PyYAML library
print_info "Installing/updating PyYAML..."
if pip3 install --user --upgrade PyYAML; then
   print_success "PyYAML installed/updated successfully."
else
   print_error "Failed to install/update PyYAML."
fi

# Install ParamSpider
# ParamSpider needs to be cloned and installed via requirements.txt
PARAMSPIDER_DIR="$HOME/tools/paramspider" # Choose an installation directory
print_info "Attempting to install/update ParamSpider in $PARAMSPIDER_DIR..."
if [ -d "$PARAMSPIDER_DIR" ]; then
  print_info "ParamSpider directory exists. Attempting to update..."
  cd "$PARAMSPIDER_DIR" || exit 1
  if git pull; then
    print_success "ParamSpider repository updated."
    # Re-install requirements in case they changed
    if pip3 install --user -r requirements.txt; then
       print_success "ParamSpider Python requirements installed/updated."
    else
       print_error "Failed to install/update ParamSpider requirements after pull."
    fi
  else
    print_error "Failed to update ParamSpider repository using 'git pull'."
  fi
  cd - > /dev/null # Go back to previous directory
else
  print_info "Cloning ParamSpider repository..."
  mkdir -p "$(dirname "$PARAMSPIDER_DIR")" # Ensure parent directory exists
  if git clone https://github.com/devanshbatham/ParamSpider "$PARAMSPIDER_DIR"; then
    print_success "ParamSpider repository cloned successfully."
    cd "$PARAMSPIDER_DIR" || exit 1
    if pip3 install --user -r requirements.txt; then
       print_success "ParamSpider Python requirements installed."
    else
       print_error "Failed to install ParamSpider requirements after clone."
    fi
    cd - > /dev/null
  else
    print_error "Failed to clone ParamSpider repository."
  fi
fi
# Remind user about ParamSpider path if needed (it's run via python3 paramspider.py)
print_warning "Remember to run ParamSpider using 'python3 $PARAMSPIDER_DIR/paramspider.py' or add an alias."


# Update Nuclei templates
print_info "Attempting to update Nuclei templates..."
if command_exists nuclei; then
  if nuclei -update-templates; then
     print_success "Nuclei templates updated successfully."
  else
     print_error "Nuclei template update command failed."
  fi
else
   print_error "Cannot update Nuclei templates because 'nuclei' command was not found (installation might have failed)."
fi


print_info "-----------------------------------------------------"
print_success "Tool installation/update process finished."
print_warning "Please check for any errors listed above."
print_warning "Ensure '$HOME/go/bin' (or your GOBIN) is in your PATH."
print_warning "Ensure Python user bin directory ('$(python3 -m site --user-base)/bin') is in your PATH if needed for pip packages."
print_info "-----------------------------------------------------"

exit 0
