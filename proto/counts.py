import json
import requests

response = requests.get("https://ontology.api.hubmapconsortium.org/organs/by-code?application_context=HUBMAP")
organ_code_map = response.json()

def convert_organ_name(organ_code):
    if organ_code in organ_code_map:
        return organ_code_map[organ_code]
    else:
        return organ_code + "-UNKNOWN"

with open('organs.json', 'r', encoding='utf-8-sig') as file:
    organs = json.load(file)
    
    
with open('datasets.json', 'r', encoding='utf-8-sig') as file:
    datasets = json.load(file)
    
with open('download-usage.json', 'r', encoding='utf-8') as file:
    usage = json.load(file)

for org in organs:
    org['name'] = convert_organ_name(org['s.organ'])
    org.pop('s.organ')

transfers = []
for dc in usage['aggregations']['calendarHistogram']['buckets']:
    trans = {"bytes_downloaded": int(dc['totalBytes']['value']),"month":dc['key_as_string']}
    transfers.append(trans)

data_out = {"organ_types": organs, "datasets": datasets, "monthly_transfer_totals": transfers}

with open('counts.json', 'w', encoding='utf-8') as file:
    json.dump(data_out, file)