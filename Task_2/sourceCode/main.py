import os
import sqlite3
import ipaddress
from flask import Flask, request, redirect, url_for, render_template_string

DB_PATH = "network_audit.db"

app = Flask(__name__)


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            hostname TEXT,
            vendor TEXT,
            has_loopback INTEGER,
            routing_protocols TEXT,
            issues TEXT
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS interfaces (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id INTEGER,
            name TEXT,
            ip_cidr TEXT,
            FOREIGN KEY(device_id) REFERENCES devices(id)
        )
    """)

    conn.commit()
    conn.close()


def detect_vendor(filename, text):
    name = filename.lower()
    if "cisco" in name:
        return "cisco"
    if "huawei" in name:
        return "huawei"
    if "juniper" in name:
        return "juniper"
    # fallback by content
    if "hostname " in text:
        return "cisco"
    if "sysname " in text:
        return "huawei"
    if "system {" in text and "host-name" in text:
        return "juniper"
    return "unknown"


def parse_cisco_like(text):
    hostname = None
    interfaces = []
    protocols = set()
    acls = []
    ospf_areas = set()
    bgp_asn = None

    current_if = None

    for raw in text.splitlines():
        line = raw.strip()

        if not line or line.startswith("!"):
            continue

        # hostname
        if line.lower().startswith("hostname "):
            hostname = line.split()[1]

        elif line.lower().startswith("sysname "):  # Huawei
            hostname = line.split()[1]

        # interfaces
        elif line.startswith("interface "):
            current_if = line.split()[1]
            interfaces.append({"name": current_if, "ip": None})

        elif line.startswith("ip address") and current_if:
            parts = line.split()
            if len(parts) >= 4:
                ip = parts[2]
                mask = parts[3]
                try:
                    net = ipaddress.ip_network(f"{ip}/{mask}", strict=False)
                    interfaces[-1]["ip"] = str(net)
                except Exception:
                    pass

        # OSPF / BGP routing
        elif line.lower().startswith("router ospf"):
            protocols.add("OSPF")
            parts = line.split()
            if len(parts) >= 3 and parts[2].isdigit():
                ospf_areas.add(int(parts[2]))  # very naive: using process-id as "area"

        elif line.lower().startswith("router bgp"):
            protocols.add("BGP")
            parts = line.split()
            if len(parts) >= 3 and parts[2].isdigit():
                bgp_asn = int(parts[2])

        # ACL-like
        elif line.startswith("access-list") or line.startswith("ip access-list"):
            acls.append(line)

    return {
        "hostname": hostname,
        "interfaces": interfaces,
        "protocols": protocols,
        "acls": acls,
        "ospf_areas": ospf_areas,
        "bgp_asn": bgp_asn,
    }


def parse_juniper(text):
    hostname = None
    interfaces = []
    protocols = set()
    acls = []
    ospf_areas = set()
    bgp_asn = None

    lines = [l.strip() for l in text.splitlines()]
    current_if = None

    for i, line in enumerate(lines):
        # hostname
        if line.startswith("host-name"):
            # host-name R3;
            parts = line.split()
            if len(parts) >= 2:
                hostname = parts[1].rstrip(";")

        # interface name
        if " {" in line and not line.startswith("system"):
            if line.split()[0].endswith("{"):
                maybe_if = line.split()[0].rstrip("{")
            else:
                maybe_if = line.split()[0]
            # very naive: Juniper interface naming
            if any(maybe_if.startswith(p) for p in ["ge-", "xe-", "lo0", "lo-"]):
                current_if = maybe_if
                interfaces.append({"name": current_if, "ip": None})

        # IP address line
        if "address" in line and "/" in line:
            parts = line.split()
            for idx, p in enumerate(parts):
                if p == "address" and idx + 1 < len(parts):
                    cidr = parts[idx + 1].rstrip(";")
                    try:
                        net = ipaddress.ip_network(cidr, strict=False)
                        if current_if:
                            interfaces[-1]["ip"] = str(net)
                    except Exception:
                        pass

        # BGP / OSPF detection
        if "protocols" in line:
            continue  # just container
        if "bgp {" in line:
            protocols.add("BGP")
        if "ospf {" in line:
            protocols.add("OSPF")

        # Juniper policy as "ACL"
        if "policy-statement" in line:
            acls.append(line)

    return {
        "hostname": hostname,
        "interfaces": interfaces,
        "protocols": protocols,
        "acls": acls,
        "ospf_areas": ospf_areas,
        "bgp_asn": bgp_asn,
    }


def parse_config(filename, text):
    vendor = detect_vendor(filename, text)

    if vendor in ("cisco", "huawei"):
        parsed = parse_cisco_like(text)
    elif vendor == "juniper":
        parsed = parse_juniper(text)
    else:
        # default: try cisco-like
        parsed = parse_cisco_like(text)

    parsed["vendor"] = vendor
    return parsed



def apply_validations(devices):
    """
    devices: list of dicts from parse_config, each extended with:
      - hostname
      - interfaces
      - protocols
      - ospf_areas
      - bgp_asn
      - vendor
    This function adds:
      - has_loopback (bool)
      - issues (list of strings)
    """
    # 1) Loopback check
    for dev in devices:
        issues = []
        has_lo = False
        for iface in dev["interfaces"]:
            name = (iface["name"] or "").lower()
            if name.startswith("loopback0") or name == "lo0":
                has_lo = True
                break
        if not has_lo:
            issues.append("Missing Loopback0/lo0 interface")
        dev["has_loopback"] = has_lo
        dev["issues"] = issues

    # 2) Subnet overlap between devices
    all_nets = []  # list of (hostname, ip_network)
    for dev in devices:
        hostname = dev["hostname"] or "UNKNOWN"
        for iface in dev["interfaces"]:
            if iface["ip"]:
                try:
                    net = ipaddress.ip_network(iface["ip"], strict=False)
                    all_nets.append((hostname, net))
                except Exception:
                    continue

    for i in range(len(all_nets)):
        host1, net1 = all_nets[i]
        for j in range(i + 1, len(all_nets)):
            host2, net2 = all_nets[j]
            if host1 == host2:
                continue
            if net1.overlaps(net2):
                msg1 = f"Subnet {net1} overlaps with {host2} ({net2})"
                msg2 = f"Subnet {net2} overlaps with {host1} ({net1})"
                for dev in devices:
                    if dev["hostname"] == host1 and msg1 not in dev["issues"]:
                        dev["issues"].append(msg1)
                    if dev["hostname"] == host2 and msg2 not in dev["issues"]:
                        dev["issues"].append(msg2)

    # 3) Very basic OSPF/BGP "consistency"
    ospf_areas_all = set()
    bgp_asn_all = set()
    for dev in devices:
        for a in dev.get("ospf_areas", []):
            ospf_areas_all.add(a)
        asn = dev.get("bgp_asn")
        if asn:
            bgp_asn_all.add(asn)

    if len(ospf_areas_all) > 1:
        for dev in devices:
            if "OSPF" in dev["protocols"]:
                dev["issues"].append("OSPF area inconsistency across devices")

    if len(bgp_asn_all) > 1:
        for dev in devices:
            if "BGP" in dev["protocols"]:
                dev["issues"].append("BGP ASN inconsistency across devices")


def save_devices_to_db(devices):
    conn = get_db()
    cur = conn.cursor()

    # simple: clear previous data
    cur.execute("DELETE FROM interfaces")
    cur.execute("DELETE FROM devices")

    for dev in devices:
        hostname = dev["hostname"] or "UNKNOWN"
        vendor = dev["vendor"]
        has_loopback = 1 if dev.get("has_loopback") else 0
        protocols_text = ",".join(sorted(dev["protocols"]))
        issues_text = "; ".join(dev["issues"])

        cur.execute(
            "INSERT INTO devices (hostname, vendor, has_loopback, routing_protocols, issues) "
            "VALUES (?, ?, ?, ?, ?)",
            (hostname, vendor, has_loopback, protocols_text, issues_text),
        )
        device_id = cur.lastrowid

        for iface in dev["interfaces"]:
            cur.execute(
                "INSERT INTO interfaces (device_id, name, ip_cidr) VALUES (?, ?, ?)",
                (device_id, iface["name"], iface["ip"]),
            )

    conn.commit()
    conn.close()



UPLOAD_FORM_HTML = """
<!doctype html>
<title>Upload Network Configs</title>
<h1>Upload device configuration files</h1>
<form method="post" enctype="multipart/form-data">
  <input type="file" name="configs" multiple>
  <input type="submit" value="Upload">
</form>
<p><a href="{{ url_for('dashboard') }}">Go to Dashboard</a></p>
"""


@app.route("/upload", methods=["GET", "POST"])
def upload():
    if request.method == "POST":
        files = request.files.getlist("configs")
        devices = []

        for f in files:
            if not f.filename:
                continue
            content = f.read().decode("utf-8", errors="ignore")
            parsed = parse_config(f.filename, content)
            devices.append(parsed)

        if not devices:
            return "No valid files uploaded", 400

        apply_validations(devices)
        save_devices_to_db(devices)

        return redirect(url_for("dashboard"))

    return render_template_string(UPLOAD_FORM_HTML)


DASHBOARD_HTML = """
<!doctype html>
<title>Network Audit Dashboard</title>
<h1>Network Audit Dashboard</h1>
<p><a href="{{ url_for('upload') }}">Upload more configs</a></p>
<table border="1" cellpadding="5" cellspacing="0">
  <tr>
    <th>Hostname</th>
    <th>Vendor</th>
    <th>Protocols</th>
    <th>Has Loopback</th>
    <th>Interface Count</th>
    <th>Issues</th>
  </tr>
  {% for d in devices %}
  <tr>
    <td>{{ d.hostname }}</td>
    <td>{{ d.vendor }}</td>
    <td>{{ d.routing_protocols }}</td>
    <td>{{ 'YES' if d.has_loopback else 'NO' }}</td>
    <td>{{ d.if_count }}</td>
    <td>{{ d.issues or '-' }}</td>
  </tr>
  {% endfor %}
</table>
"""


@app.route("/dashboard")
def dashboard():
    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT * FROM devices")
    rows = cur.fetchall()

    devices = []
    for row in rows:
        cur.execute("SELECT COUNT(*) FROM interfaces WHERE device_id = ?", (row["id"],))
        if_count = cur.fetchone()[0]
        devices.append({
            "hostname": row["hostname"],
            "vendor": row["vendor"],
            "routing_protocols": row["routing_protocols"],
            "has_loopback": bool(row["has_loopback"]),
            "issues": row["issues"],
            "if_count": if_count,
        })

    conn.close()
    return render_template_string(DASHBOARD_HTML, devices=devices)



if __name__ == "__main__":
    init_db()
    app.run(debug=True)
