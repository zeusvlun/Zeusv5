#!/bin/bash

# zeusv5 - Enhanced Automated Recon Script
# Author: Zeusvlun

# Color Codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Message Functions
print_message() {
    echo -e "${BLUE}[*]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[+]${NC} $1"
}

print_error() {
    echo -e "${RED}[-]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

# OS Check
check_os() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        print_message "Running on Linux."
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        print_message "Running on macOS."
    else
        print_error "Unsupported OS. Exiting..."
        exit 1
    fi
}

# Tool Installation and Update
install_tool() {
    if ! command -v $1 &> /dev/null; then
        print_warning "Tool '$1' is not installed. Attempting to install..."
        case $1 in
            secretfinder)
                git clone https://github.com/m4ll0k/SecretFinder.git ~/tools/SecretFinder
                pip install -r ~/tools/SecretFinder/requirements.txt
                ln -s ~/tools/SecretFinder/SecretFinder.py /usr/local/bin/secretfinder
                ;;
            nuclei)
                go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
                ;;
            amass)
                go install -v github.com/owasp/amass/v3/...@latest
                ;;
            sqlmap)
                git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git ~/tools/sqlmap
                ;;
            dialog)
                sudo apt-get install dialog
                ;;
            whatweb)
                gem install whatweb
                ;;
            gospider)
                go install github.com/jaeles-project/gospider@latest
                ;;
            pandoc)
                sudo apt-get install pandoc
                ;;
            weasyprint)
                pip install weasyprint
                ;;
            *)
                print_warning "Default installation logic used for $1..."
                ;;
        esac
    else
        print_success "Tool '$1' is already installed."
    fi
}

# Update Tools
update_tools() {
    print_message "Updating tools..."
    for tool in "${required_tools[@]}"; do
        case $tool in
            nuclei)
                nuclei -update-templates
                ;;
            *)
                print_message "No update available for $tool."
                ;;
        esac
    done
}

# Report Generation
generate_report() {
    print_message "Generating report..."
    report_file="$base_dir/report_$(date +%Y%m%d_%H%M%S).html"
    echo "<html><body><h1>Recon Report for $domain</h1>" > $report_file
    echo "<h2>Subdomains</h2><pre>$(cat subs/live.txt)</pre>" >> $report_file
    echo "<h2>Parameters</h2><pre>$(cat params/all-parameters.txt)</pre>" >> $report_file
    echo "<h2>Secrets</h2><pre>$(cat secrets/all_secrets.txt)</pre>" >> $report_file
    echo "<h2>Vulnerabilities</h2><pre>$(cat bugs/vulnerabilities.txt)</pre>" >> $report_file
    echo "</body></html>" >> $report_file
    print_success "Report generated at $report_file"
}

# Required Tools
required_tools=(subdominator httpx waybackurls gau nuclei kxss gf ffuf wfuzz dnsrecon nmap wpscan exiftool secretfinder amass sqlmap dialog whatweb gospider crawlergo pandoc weasyprint)

# OS Check
check_os

# Install/Update Tools
print_message "Verifying and updating tools..."
for tool in "${required_tools[@]}"; do
    install_tool $tool
done
update_tools
print_success "Tools are installed and updated."

# Project Data
print_message "Enter project name:"
read project_name
base_dir=~/recon/$project_name
mkdir -p $base_dir/{subs,params,bugs,js_files,extra,endpoints,secrets,cms,web}
cd $base_dir || exit

print_message "Enter target domain:"
read domain

# CMS Detection
detect_cms() {
    print_message "Detecting CMS..."
    whatweb $domain > cms/cms_detection.txt
    if grep -i "WordPress" cms/cms_detection.txt; then
        cms="WordPress"
        print_success "Detected CMS: WordPress"
    else
        cms="Unknown"
        print_warning "CMS not detected or not supported."
    fi
}

# Task Functions
run_subdomain_enum() {
    print_message "Enumerating subdomains..."
    amass enum -d $domain -o subs/amass_subdomains.txt
    subdominator -d $domain -o subs/subdominator_subdomains.txt
    cat subs/amass_subdomains.txt subs/subdominator_subdomains.txt | sort -u | httpx -silent -o subs/live.txt
}

run_param_collection() {
    print_message "Collecting parameters..."
    cat subs/live.txt | waybackurls | grep "=" | tee params/waybackurls.txt
    cat subs/live.txt | gau | grep "=" | tee params/gau.txt
    cat params/*.txt | sort -u | tee params/all-parameters.txt
}

run_js_analysis() {
    print_message "Extracting and analyzing JavaScript files..."
    mkdir -p js_files/js_downloaded
    cat subs/live.txt | grep ".js" | tee js_files/js_files_list.txt
    cat js_files/js_files_list.txt | xargs -n 1 -P 5 wget -q -P js_files/js_downloaded/
    print_message "Searching for secrets in JavaScript files using SecretFinder..."
    for js_file in js_files/js_downloaded/*; do
        secretfinder -i "$js_file" -o cli | tee -a secrets/js_secrets.txt
    done
}

run_secret_analysis() {
    print_message "Running SecretFinder on all collected links..."
    cat subs/live.txt | secretfinder -o cli | tee secrets/all_secrets.txt
}

run_nuclei_scans() {
    print_message "Running Nuclei scans for various vulnerabilities..."
    nuclei -l subs/live.txt -t ~/nuclei-templates/ -o bugs/nuclei_vulns.txt
}

run_additional_scans() {
    print_message "Running additional scans (e.g., XSS)..."
    cat params/all-parameters.txt | kxss | grep "< >" | tee bugs/kxss.txt
}

run_endpoint_fuzzing() {
    print_message "Fuzzing endpoints..."
    ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt:FUZZ -u http://$domain/FUZZ -o endpoints/ffuf_endpoints.txt
}

run_dns_enum() {
    print_message "Running DNS enumeration..."
    dnsrecon -d $domain -a | tee extra/dns_info.txt
}

run_protocol_analysis() {
    print_message "Running protocol analysis..."
    nmap -p 21,22,80,443 $domain -oN extra/protocol_scan.txt
}

run_metadata_extraction() {
    print_message "Extracting metadata..."
    wget -i params/all-parameters.txt -P extra/downloaded_files
    exiftool extra/downloaded_files/* | tee extra/file_metadata.txt
}

run_cms_specific_scans() {
    if [[ $cms == "WordPress" ]]; then
        print_message "Running WordPress scans..."
        wpscan --url $domain --enumerate vp,vt,u || print_error "WPScan failed."
    else
        print_warning "Skipping CMS-specific scans as no supported CMS was detected."
    fi
}

run_web_crawling() {
    print_message "Starting web crawling..."
    gospider -s $domain -t 20 -w | tee web/crawled_urls.txt
}

run_sqlmap_scan() {
    print_message "Running sqlmap scans..."
    sqlmap -u $domain --batch --level 5 --risk 3 -o
}

generate_pdf_report() {
    print_message "Generating PDF report..."
    pandoc report.html -o report.pdf
}

# Text-Based GUI using dialog
show_menu() {
    choices=$(dialog --menu "Select Task" 20 50 15 \
    1 "Subdomain Enumeration" \
    2 "Parameter Collection" \
    3 "JavaScript Analysis" \
    4 "Secret Analysis (All Links)" \
    5 "Nuclei Scans" \
    6 "Additional Scans" \
    7 "Endpoint Fuzzing" \
    8 "DNS Enumeration" \
    9 "Protocol Analysis" \
    10 "Metadata Extraction" \
    11 "CMS Detection and Scans" \
    12 "Web Crawling" \
    13 "SQL Injection Testing" \
    14 "Generate PDF Report" \
    15 "Run All Tasks" \
    2>&1 >/dev/tty)
    choice=$(echo $choices | awk '{print $1}')
}

# Main Script Execution
show_menu

case $choice in
    1) run_subdomain_enum ;;
    2) run_param_collection ;;
    3) run_js_analysis ;;
    4) run_secret_analysis ;;
    5) run_nuclei_scans ;;
    6) run_additional_scans ;;
    7) run_endpoint_fuzzing ;;
    8) run_dns_enum ;;
    9) run_protocol_analysis ;;
    10) run_metadata_extraction ;;
    11)
        detect_cms
        run_cms_specific_scans
        ;;
    12) run_web_crawling ;;
    13) run_sqlmap_scan ;;
    14) generate_pdf_report ;;
    15)
        run_subdomain_enum
        run_param_collection
        run_js_analysis
        run_secret_analysis
        run_nuclei_scans
        run_additional_scans
        run_endpoint_fuzzing
        run_dns_enum
        run_protocol_analysis
        run_metadata_extraction
        detect_cms
        run_cms_specific_scans
        run_web_crawling
        run_sqlmap_scan
        generate_pdf_report
        ;;
    *)
        print_error "Invalid choice!"
        exit 1
        ;;
esac

# Generate Report
generate_report

print_success "Task completed. Results are saved in $base_dir."
