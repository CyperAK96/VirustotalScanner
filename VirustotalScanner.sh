#!/bin/bash

# Function to check if an IP address is malicious using VirusTotal
check_malicious() {
    local api_key="$1"  # Pass the API key as an argument

    # Iterate over each IP address
    while read -r ip_address; do
        # Perform API request to VirusTotal
        response=$(curl -s "https://www.virustotal.com/api/v3/ip_addresses/$ip_address" -H "x-apikey: $api_key")

        # Extract relevant information from the response
        malicious=$(echo "$response" | jq -r '.data.attributes.last_analysis_stats.malicious')
        
        # Print the result
        echo "IP address: $ip_address"
        if [ "$malicious" == "null" ]; then
            echo "Malicious: Unknown"
        elif [ "$malicious" == 0 ]; then
            echo "Malicious: No"
        else
            echo "Malicious: Yes"
        fi
    done
}

# Prompt the user to enter the VirusTotal API key
read -p "Enter your VirusTotal API key: " api_key

# Prompt the user to enter the Wireshark file name
read -p "Enter the Wireshark file name: " file_name

# Check if the file exists
if [ -f "$file_name" ]; then
    # Use tshark to print packet details
    
    # Extract the IP address using awk
    tshark -r "$file_name" -T fields -e ip.dst | awk '!/^10\.|^172\.(1[6-9]|2[0-9]|3[0-1])\.|^192\.168\./' | sort -u | check_malicious "$api_key"
else
    echo "File not found: $file_name"
fi
