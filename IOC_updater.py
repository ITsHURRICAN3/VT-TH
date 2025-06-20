import requests

id_coll = input("Insert collection ID:")

url = "https://www.virustotal.com/api/v3/collections/" + id_coll

print(url)

api_key = input("Insert VT API key:")

headers = {
    "X-Apikey": api_key,
    "accept": "application/json",
    "content-type": "application/json"
}

IOC = input("Insert an IOC:")

payload = { "data": {
		"attributes": {
			"name": "Updating the collection"
		},
		"raw_items": IOC,
		"type": "collection"
	}}

response = requests.patch(url, json=payload,headers=headers)

print(response.text)