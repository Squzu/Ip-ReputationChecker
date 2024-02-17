from flask import Flask, request, render_template
import requests

app = Flask(__name__)

# VirusTotal API keys
VT_API_KEYS = ["your_VT_API_key_1", "your_VT_API_key_2", "your_VT_API_key_3"]
vt_key_index = 0

# AbuseIPDB API keys
ABUSEIPDB_API_KEYS = ["your_AbuseIPDB_API_key_1", "your_AbuseIPDB_API_key_2", "your_AbuseIPDB_API_key_3"]
abuseipdb_key_index = 0

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/lookup")
def lookup():
    global vt_key_index, abuseipdb_key_index
    
    ip_address = request.args.get("ip")

    if not ip_address:
        return "IP address is required."

    # VirusTotal API request
    vt_url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
    vt_headers = {
        "accept": "application/json",
        "x-apikey": VT_API_KEYS[vt_key_index]
    }
    vt_response = requests.get(vt_url, headers=vt_headers)
    vt_data = vt_response.json()
    vt_malicious_value = vt_data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0)

    # AbuseIPDB API request
    abuseipdb_url = "https://api.abuseipdb.com/api/v2/check"
    abuseipdb_params = {
        "ipAddress": ip_address,
        "maxAgeInDays": 90,
        "verbose": ""
    }
    abuseipdb_headers = {
        "Key": ABUSEIPDB_API_KEYS[abuseipdb_key_index],
        "Accept": "application/json"
    }
    abuseipdb_response = requests.get(abuseipdb_url, params=abuseipdb_params, headers=abuseipdb_headers)
    abuseipdb_data = abuseipdb_response.json()
    abuseipdb_abuse_confidence_score = abuseipdb_data.get("data", {}).get("abuseConfidenceScore", 0)
    isp = abuseipdb_data.get("data", {}).get("isp", "Unknown")
    country = abuseipdb_data.get("data", {}).get("countryName", "Unknown")

    # Update key indices for next request
    vt_key_index = (vt_key_index + 1) % len(VT_API_KEYS)
    abuseipdb_key_index = (abuseipdb_key_index + 1) % len(ABUSEIPDB_API_KEYS)

    # Format the output
    output = f"VirusTotal: {vt_malicious_value}/90\n"
    output += f"AbuseIPDB Confidence: {'100%' if abuseipdb_abuse_confidence_score > 90 else str(abuseipdb_abuse_confidence_score) + '%'}\n"
    output += f"ISP From AbuseIPDB: {isp}\n"
    output += f"Country From AbuseIPDB: {country}"

    return output

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=True)
