import requests

collection_id = input("Insert collection ID: ")
api_key = input("Insert VT API key: ")

url = "https://www.virustotal.com/api/v3/collections/" + collection_id

headers = {
    "X-Apikey": api_key,
    "accept": "application/json",
    "content-type": "application/json"
}

# Check API key validity
test_response = requests.get(url, headers=headers)
try:
    test_json = test_response.json()
    if "error" in test_json:
        error_code = test_json["error"].get("code", "")
        error_message = test_json["error"].get("message", "")
        print(f"API Key test failed: {error_code} - {error_message}")
        exit(1)
    else:
        print("API Key is valid. You can now insert IOCs.")
except Exception as e:
    print(f"Error validating API key: {str(e)}")
    exit(1)

while True:
    ioc = input("Insert an IOC (or type 'exit' to quit): ")
    if ioc.lower() == 'exit':
        print("Exiting the program...")
        break

    payload = {
        "data": {
            "attributes": {
            },
            "raw_items": ioc,
            "type": "collection"
        }
    }

    try:
        response = requests.patch(url, json=payload, headers=headers)
        resp_json = response.json()
        # Check for error in the response
        if "error" in resp_json:
            error_code = resp_json["error"].get("code", "")
            error_message = resp_json["error"].get("message", "")
            print(f"Error: {error_code} - {error_message}")
        elif resp_json == {}:
            print("Insertion failed! The response is empty ({}).")
        elif 'data' in resp_json:
            print("Insertion succeeded!")
        else:
            print("⚠️ Unexpected API response:")
            print(resp_json)
    except Exception as e:
        print(f"Error occurred: {str(e)}")