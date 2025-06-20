import requests
from datetime import datetime, UTC

collection_id = input("Insert collection ID: ")
api_key = input("Insert VT API key: ")

url = f"https://www.virustotal.com/api/v3/collections/{collection_id}"

headers = {
    "X-Apikey": api_key,
    "accept": "application/json",
    "content-type": "application/json"
}

check = requests.get(url, headers=headers)
try:
    check_json = check.json()
    if "error" in check_json:
        error_code = check_json["error"].get("code", "")
        error_message = check_json["error"].get("message", "")
        if error_code == "NotFoundError":
            print(f"❌ Collection not found: {error_code} - {error_message}")
            exit(1)
        else:
            print(f"❌ Error: {error_code} - {error_message}")
            exit(1)
    elif "data" in check_json:
        print("✅ Collection exists. Here are the collection details:")
        attributes = check_json["data"].get("attributes", {})
        print("Name:", attributes.get("name", "N/A"))
        creation_ts = attributes.get("creation_date", None)
        last_mod_ts = attributes.get("last_modification_date", None)
        if isinstance(creation_ts, int):
            creation_date = datetime.fromtimestamp(creation_ts, UTC).strftime('%Y-%m-%d %H:%M:%S')
        else:
            creation_date = "N/A"
        if isinstance(last_mod_ts, int):
            last_mod_date = datetime.fromtimestamp(last_mod_ts, UTC).strftime('%Y-%m-%d %H:%M:%S')
        else:
            last_mod_date = "N/A"
        print("Creation date:", creation_date)
        print("Last modification date:", last_mod_date)
        counters = attributes.get("counters", {})
        print("Number of IOCs:", counters.get("iocs", "N/A"))
        print("Files:", counters.get("files", "N/A"))
        print("Domains:", counters.get("domains", "N/A"))
        print("IP addresses:", counters.get("ip_addresses", "N/A"))
        print("URLs:", counters.get("urls", "N/A"))
    else:
        print("⚠️ Unexpected response while checking collection:")
        print(check_json)
        exit(1)
except Exception as e:
    print(f"Error checking collection: {str(e)}")
    exit(1)

while True:
    ioc = input("Insert an IOC (or type 'exit' to quit): ")
    if ioc.lower() == 'exit':
        print("Exiting the program...")
        break

    payload = {
        "data": {
            "attributes": {
                "name": attributes.get("name")
            },
            "raw_items": ioc,
            "type": "collection"
        }
    }

    try:
        response = requests.patch(url, json=payload, headers=headers)
        resp_json = response.json()
        if "error" in resp_json:
            error_code = resp_json["error"].get("code", "")
            error_message = resp_json["error"].get("message", "")
            print(f"❌ Error: {error_code} - {error_message}")
        elif resp_json == {}:
            print("❌ Insertion failed! The response is empty ({}).")
        elif 'data' in resp_json:
            print("✅ Insertion succeeded!")
        else:
            print("⚠️ Unexpected API response:")
            print(resp_json)
    except Exception as e:
        print(f"Error occurred: {str(e)}")