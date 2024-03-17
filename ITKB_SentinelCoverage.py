import json 
import json
import requests

banner = """
Insider-Threat-TTP-Knowledge-Base - Microsoft Sentinel-Coverage
"""
print(banner)

# Configuration Parameters
Azure_AD_Tenant = "TENANTID_HERE"
Client_ID = "CLIENTID_HERE"
Client_Secret = "CLIENTSECRET_HERE"
ResourceGroup = "RG_NAME_HERE"
WorkspaceID = "WORKSPACEID_HERE"
Subscription = "SUBSCRIPTIONID_HERE"


# Get the Access Token
LAW_Access_Url = "https://login.microsoftonline.com/"+Azure_AD_Tenant+"/oauth2/token"
LAW_headers = {'Content-Type': 'application/x-www-form-urlencoded'}
LAW_payload='grant_type=client_credentials&client_id='+ Client_ID+'&resource=https://api.loganalytics.io&client_secret='+Client_Secret
LAW_Access_response = requests.get(LAW_Access_Url, headers=LAW_headers, data=LAW_payload).json()
LAW_Access_Token = LAW_Access_response["access_token"]
print("[+] Access Token Received Successfully")

LAW_Auth = 'Bearer '+LAW_Access_Token
LAW_headersAD = {
    'Authorization': LAW_Auth}

LAW_Url= "https://api.loganalytics.io/v1/workspaces/"+WorkspaceID+"/query"

# Get the MITRE ATT&CK Techniques from Microsoft Sentinel Alerts
LAW_Payload = {"query": "SecurityAlert| where TimeGenerated > ago(90d)| where isnotempty(Techniques)| summarize count() by Techniques| project Techniques"}
LAW_response = requests.post(LAW_Url, headers=LAW_headersAD, json=LAW_Payload).json()

Sentinel_Techniques = []

for technique in LAW_response["tables"][0]["rows"]:
    Technique = json.loads(technique[0])
    for t in Technique:
        Sentinel_Techniques.append(t)

# Remove Duplicates
Sentinel_Techniques =  list(dict.fromkeys(Sentinel_Techniques))
print("[+] MITRE ATT&CK Techniques were extracted from your Microsoft Sentinel Alerts Successfully")

# Load Insider Threat TTPs JSON file
with open('InsiderThreatTTP_KB.json') as f:
    InsiderKbData = json.load(f)

InsiderThreatTTPs = []
for i in range(len(InsiderKbData["techniques"])):
    InsiderThreatTTPs.append(InsiderKbData["techniques"][i]["techniqueID"])
#print(InsiderThreatTTPs)

# Get the common techniques between the Insider Threat TTPs and the Sentinel Techniques
Common_Techniques = list(set(InsiderThreatTTPs) & set(Sentinel_Techniques))
print("[+] Common Techniques between Insider Threat TTPs and Sentinel Techniques were extracted Successfully")
#print(Common_Techniques)

# Generate MITRE Layer

Layer_Template = {
    "description": "Techniques Covered by Microsoft Sentinel",
    "name": "Techniques Covered by Microsoft Sentinel",
    "domain": "mitre-enterprise",
    "version": "4.5",
    "techniques": 
        [{  "techniqueID": technique, "color": "#5df542"  } for technique in Common_Techniques] 
    ,
    "gradient": {
        "colors": [
            "#ffffff",
            "#5df542"
        ],
        "minValue": 0,
        "maxValue": 1
    },
    "legendItems": [
        {
            "label": "Techniques Covered by Microsoft Sentinel",
            "color": "#ff0000"
        }
    ]
}

json_data = json.dumps(Layer_Template)

with open("CoveredTTPs.json", "w") as file:
    json.dump(Layer_Template, file)

# Techiques not covered by Microsoft Sentinel

Not_Covered_Techniques = list(set(InsiderThreatTTPs) - set(Sentinel_Techniques))

Layer_Template2 = { 
    "description": "Techniques Not Covered by Microsoft Sentinel",
    "name": "Techniques Not Covered by Microsoft Sentinel",
    "domain": "mitre-enterprise",
    "version": "4.5",
    "techniques": 
        [{  "techniqueID": technique, "color": "#ff0000"  } for technique in Not_Covered_Techniques] 
    ,
    "gradient": {
        "colors": [
            "#ffffff",
            "#ff0000"
        ],
        "minValue": 0,
        "maxValue": 1
    },
    "legendItems": [
        {
            "label": "Techniques Not Covered by Microsoft Sentinel",
            "color": "#ff0000"
        }
    ]
}

json_data = json.dumps(Layer_Template2)

with open("NotCoveredTTPs.json", "w") as file:
    json.dump(Layer_Template2, file)

print("[+] The MITRE matrix json files 'CoveredTTPs.json' and 'NotCoveredTTPs.json' were created successfully")

