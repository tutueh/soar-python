import sys
import os
import json
import yaml
from datetime import datetime, timezone, timedelta
from jinja2 import Template

def open_file(path, loader=json.load):
    with open(path, "r") as f:
        return loader(f)

def collect_iocs(alert):
    out = []
    indicators = alert.get("indicators", {})
    for typeioc, values in indicators.items():
        typ = {"domains": "domain", "ipv4": "ipv4", "urls": "url", "sha256": "sha256"}.get(typeioc, "Undefined")
        
        for val in values:
            out.append({"type": typ, "value": val})
    return out

def enrich_iocs(iocs, provider_dirs):
    providers = ["defender_ti", "reversinglabs", "anomali"]

    for ioc in iocs:
        ioc["risk"] = {"verdict": "unknown", "score": 0, "sources": []}
        verdicts = []
        scores = []

        real_type = ioc["type"] if ioc["type"] != "ipv4" else "ip"

        for p in providers:
            base_path = provider_dirs.get(p, "./mocks/it").rstrip("/")
            filename = f"{p}_{real_type}_{ioc['value']}.json"
            filepath = base_path + "/" + filename

            # print (filepath)

            if os.path.isfile(filepath):
                data = open_file(filepath, json.load)
                ioc["risk"]["sources"].append(p)

                v, s = "unknown", 0
                if p == "anomali":
                    v = data.get("risk", "unknown")
                    s = data.get("confidence", 0)
                elif p == "defender_ti":
                    v = data.get("reputation", "unknown")  
                    s = data.get("score", 0)
                elif p == "reversinglabs":
                    v = data.get("classification", "unknown")
                    s = data.get("score", 0)

                verdicts.append(v)
                scores.append(s)

        if len(scores) > 0:
            ioc["risk"]["score"] = max(scores)
            if "malicious" in verdicts:
                ioc["risk"]["verdict"] = "malicious"
            elif "suspicious" in verdicts:
                ioc["risk"]["verdict"] = "suspicious"
            elif "clean" in verdicts:
                ioc["risk"]["verdict"] = "clean"
        else:
            ioc["risk"]["sources"] = ["unknown"]

    return iocs

def calc_triage(alert, iocs, allowlist, mitre_map):
    bases = {"Malware": 70, "Phishing": 60, "Beaconing": 65, "CredentialAccess": 75, "C2": 80}
    
    alert_type = alert.get("type", "Unknown")
    severity = bases.get(alert_type, 40)
    tags = []
    suppressed = False

    bad_iocs = [i for i in iocs if i["risk"]["verdict"] in ["malicious", "suspicious"]]
    malicious_count = len([i for i in iocs if i["risk"]["verdict"] == "malicious"])
    suspicious_count = len([i for i in iocs if i["risk"]["verdict"] == "suspicious"])

    if malicious_count > 0:
        severity += 20
    if suspicious_count > 0:
        severity += 10
    
    extra_bad = len(bad_iocs) - 1
    if extra_bad > 0:
        severity += min(extra_bad * 5, 20)

    asset = alert.get("asset", {})
    device_id = asset.get("device_id")
    allowlisted_iocs = 0

    for ioc in iocs:
        if ioc["type"] in allowlist and ioc["value"] in allowlist[ioc["type"]]:
            allowlisted_iocs += 1
            if "allowlisted" not in tags:
                tags.append("allowlisted")

    if device_id and device_id in allowlist.get("device_ids", []):
        if "allowlisted" not in tags:
            tags.append("allowlisted")

    if allowlisted_iocs == len(iocs) and len(iocs) > 0:
        severity = 0
        suppressed = True
        tags.append("suppressed")

    severity = max(0, min(100, severity))

    bucket = "Unknown"
    if severity == 0:
        bucket = "Suppressed"
    elif severity <= 39:
        bucket = "Low"
    elif severity <= 69:
        bucket = "Medium"
    elif severity <= 89:
        bucket = "High"
    else:
        bucket = "Critical"

    techniques = mitre_map.get(alert_type, ["T1040"])

    result = {
        "severity": severity,
        "bucket": bucket,
        "tags": tags,
        "suppressed": suppressed,
        "mitre": {"techniques": techniques}
    }
    return result

def write_summary(incident, outdir):
    template_str = """
# Incident Report {{ incident.incident_id }}

**Asset:** {{ incident.asset.hostname }} ({{ incident.asset.ip }})  
**Severity:** {{ incident.triage.severity }} ({{ incident.triage.bucket }})  
**Tags:** {{ incident.triage.tags|join(", ") if incident.triage.tags else "none" }}

## Indicators

{% for i in incident.indicators %}
 * **{{ i.value }}** ({{ i.type }}) - Verdictt: {{ i.risk.verdict }} | Score: {{ i.risk.score }} | Allowlisted: {{ i.allowlisted }}
{% endfor %}

## MITRE ATT&CK
{{ incident.mitre.techniques|join(", ") }}

## Response
{% if incident.actions %}
{% for action in incident.actions %}
- {{ action.type|title }} target {{ action.target }} → {{ action.result }}
{% endfor %}
{% else %}
 No automated response actions were taken.
{% endif %}

## Timeline
{% for event in incident.timeline %}
- **{{ event.stage|title }}** ({{ event.ts }}) - {{ event.details }}
{% endfor %}
"""
    
    template = Template(template_str)
    markdown = template.render(incident=incident)

    if not os.path.exists(outdir):
        os.makedirs(outdir)
    
    filepath = os.path.join(outdir, incident['incident_id'] + ".md")
    with open(filepath, "w") as f:
        f.write(markdown)
    print("Summary markdown saved:", filepath)

def save_outputs(alert, enriched_iocs, triage_result, allowlist):
    incident_id = alert.get("alert_id")
    asset_info = alert.get("asset", {})
    # now = now = datetime.now()
    tz = timezone(timedelta(hours=-3))
    timestamp = datetime.now(tz).isoformat()

    # os.makedirs('./out', exist_ok=True)
    os.makedirs("out/incidents", exist_ok=True)
    os.makedirs("out/summaries", exist_ok=True)

    device_id = asset_info.get("device_id")
    asset_allowlisted = device_id and device_id in allowlist.get("device_ids", [])

    for ioc in enriched_iocs:
        ioc["allowlisted"] = ioc["type"] in allowlist and ioc["value"] in allowlist[ioc["type"]]

    actions_taken = []
    if triage_result["severity"] >= 70 and device_id and not asset_allowlisted:
        log_entry = f"{timestamp} - device_id={device_id} incident={incident_id} result=isolated\n"
        with open("out/isolation.log", "a") as logfile:
            logfile.write(log_entry)

        actions_taken.append({
            "type": "isolate",
            "target": "device:" + device_id,
            "result": "isolated",
            "ts": timestamp
        })

    timeline_events = [
        {"stage": "ingest", "ts": timestamp, "details": "Alert processed"},
        {"stage": "enrich", "ts": timestamp, "details": "IOCs enriched with Offline Mock Data"},
        {"stage": "triage", "ts": timestamp, "details": "Severity: " + str(triage_result["severity"])}
    ]
    
    if len(actions_taken) > 0:
        timeline_events.append({"stage": "respond", "ts": timestamp, "details": "Device isolation initiated"})

    incident_data = {
        "incident_id": incident_id,
        "source_alert": alert,
        "asset": {
            "device_id": asset_info.get("device_id"),
            "hostname": asset_info.get("hostname"), 
            "ip": asset_info.get("ip")
        },
        "indicators": enriched_iocs,
        "triage": triage_result,
        "mitre": triage_result.get("mitre", {}),
        "actions": actions_taken,
        "timeline": timeline_events
    }

    incident_path = "out/incidents/" + incident_id + ".json"
    with open(incident_path, "w") as f:
        json.dump(incident_data, f, indent=4)
        #print (json.dump(incident_data, f, indent=4))
    print("Incident details saved in", incident_path)
    if actions_taken:
        print("Isolation logs in out/isolation.log")

    write_summary(incident_data, "out/summaries")

def main():
    if len(sys.argv) < 2:
        print("Correct way - python main.py <file.json>")
        exit(1)

    alert_data = open_file(sys.argv[1], json.load)
    allowlist_config = open_file("./configs/allowlists.yml", yaml.safe_load)
    mitre_config = open_file("./configs/mitre_map.yml", yaml.safe_load)
    connector_config = open_file("./configs/connectors.yml", yaml.safe_load)

    allowlist = {}
    indicators_allow = allowlist_config.get("indicators", {})
    assets_allow = allowlist_config.get("assets", {})
    
    allowlist["ipv4"] = set(indicators_allow.get("ipv4", []))
    allowlist["domain"] = set(indicators_allow.get("domains", []))
    allowlist["url"] = set(indicators_allow.get("urls", []))
    allowlist["sha256"] = set(indicators_allow.get("sha256", []))
    allowlist["device_ids"] = set(assets_allow.get("device_ids", []))

    mitre_mapping = mitre_config.get("types", {})

    provider_paths = {}
    providers_config = connector_config.get("providers", {})
    for provider_name in ["defender_ti", "reversinglabs", "anomali"]:
        provider_paths[provider_name] = providers_config.get(provider_name, {}).get("base_url", "./mocks/it")

    iocs_collected = collect_iocs(alert_data)
    iocs_enriched = enrich_iocs(iocs_collected, provider_paths)
    # print (iocs_enriched)
    triage_result = calc_triage(alert_data, iocs_enriched, allowlist, mitre_mapping)
    save_outputs(alert_data, iocs_enriched, triage_result, allowlist)

if __name__ == "__main__":
    main()
