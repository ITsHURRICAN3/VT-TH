# VT Hunting - IOC updater
Python tool used mainly for threat hunting activities, automating the interaction with VT IOCs collection

## Requirements
- Python >= 3.13.2
- requests module
- datetime module (part of standard library)
- getpass module (part of standard library)

## Usage
To quickly get started, simply run:
```sh
python IOC_updater.py
```
You will be prompted to enter your collection ID and your VirusTotal API key (the key input is hidden for security).  
You can then choose to add IoCs either manually or by providing a text file containing a list of IoCs.  
The script will validate the IoCs before submitting them to your VirusTotal collection.

For detailed instructions, advanced options, and troubleshooting, please refer to the [USER GUIDE](USER_GUIDE_ENG.pdf) included in this repository.  
([italian version](USER_GUIDE_ITA.pdf) available too!)

## VT Docs
- References: [VT Documentation](https://docs.virustotal.com/reference)
