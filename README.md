# VT Hunting
Python tool used mainly for threat hunting activities, automating the interaction with VT IOCs collection

## Requirements
- Python >= 3.13.2
- requests module
- datetime module (usually pre-installed)
- getpass module

## Usage
- Run IOC_updater.py
- Insert a collection ID, you can get it from the URL:![immagine](https://github.com/user-attachments/assets/83d4f78a-9f8b-47a7-a66e-da6040cec669)
- Insert your VT API Key, available from the profile tab.
- If both the API key and the collection ID are valid, you'll be able to insert the IOCs in the collection directly from CLI in two different ways:
  - Manually: insert a single or list of IoC(s) separated by comma.
  - From file: insert the filepath in which the IoCs are stored. An ideal file would have IoCs separated by a comma or on single lines.

## VT Docs
- References: [VT Documentation](https://docs.virustotal.com/reference)
