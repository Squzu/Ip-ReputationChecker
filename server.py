from flask import Flask, request, render_template
import requests

app = Flask(__name__)

# VirusTotal API key
VT_API_KEY = "864ce0b4fa3c17b416a2d375e41c88fb3d89ba79668797f75b2c502fbfe20fbe"

# AbuseIPDB API key
ABUSEIPDB_API_KEY = "5ee9adb87d5dcf735f7a8bd1d517b24f7a786273fdf5f9ab8dfac148bdd4147dac8d994e31e41bab"

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/lookup")
def lookup():
    ip_address = request.args.get("ip")

    if not ip_address:
        return "IP address is required."

    # VirusTotal API request
    vt_url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
    vt_headers = {
        "accept": "application/json",
        "x-apikey": VT_API_KEY
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
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json"
    }
    abuseipdb_response = requests.get(abuseipdb_url, params=abuseipdb_params, headers=abuseipdb_headers)
    abuseipdb_data = abuseipdb_response.json()
    abuseipdb_abuse_confidence_score = abuseipdb_data.get("data", {}).get("abuseConfidenceScore", 0)
    isp = abuseipdb_data.get("data", {}).get("isp", "Unknown")
    country = abuseipdb_data.get("data", {}).get("countryName", "Unknown")

    # Format the output
    output = f"VirusTotal: {vt_malicious_value}/90\n"
    output += f"AbuseIPDB Confidence: {'100%' if abuseipdb_abuse_confidence_score > 90 else str(abuseipdb_abuse_confidence_score) + '%'}\n"
    output += f"ISP From AbuseIPDB: {isp}\n"
    output += f"Country From AbuseIPDB: {country}"

    return output

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=True)
