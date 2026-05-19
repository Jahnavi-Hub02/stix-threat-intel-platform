import sqlite3
from datetime import datetime, timezone

DB = 'database/threat_intel.db'
conn = sqlite3.connect(DB)
cursor = conn.cursor()

# IPs from your SSH_sample.log.log file
ssh_ips = [
    '173.234.31.186',
    '52.80.34.196',
    '202.100.179.208',
    '5.36.59.76',
]

print("=== Checking SSH log IPs against IOC database ===\n")
for ip in ssh_ips:
    cursor.execute("SELECT ioc_value, severity, confidence FROM ioc_indicators WHERE ioc_value=? AND is_active=1", (ip,))
    row = cursor.fetchone()
    if row:
        print(f"MATCH FOUND: {ip} | severity: {row[1]} | confidence: {row[2]}")
    else:
        print(f"NOT IN DB:   {ip}")

print("\n=== Inserting SSH IPs into IOC database for demo ===\n")

now = datetime.now(timezone.utc).isoformat()

iocs_to_insert = [
    {
        'stix_id':    'indicator--ssh-brute-001',
        'ioc_type':   'ipv4-addr',
        'ioc_value':  '173.234.31.186',
        'confidence': 85,
        'severity':   'high',
        'source':     'SSH_brute_force_log',
        'is_active':  1,
        'first_seen': now,
        'last_seen':  now,
        'country':    'US',
        'tlp':        'GREEN',
        'tags':       'brute-force,ssh,malicious-activity',
        'description':'SSH brute force attacker observed in SSH_sample.log'
    },
    {
        'stix_id':    'indicator--ssh-brute-002',
        'ioc_type':   'ipv4-addr',
        'ioc_value':  '52.80.34.196',
        'confidence': 80,
        'severity':   'high',
        'source':     'SSH_brute_force_log',
        'is_active':  1,
        'first_seen': now,
        'last_seen':  now,
        'country':    'CN',
        'tlp':        'GREEN',
        'tags':       'brute-force,ssh,invalid-user',
        'description':'SSH invalid user attacker observed in SSH_sample.log'
    },
    {
        'stix_id':    'indicator--ssh-brute-003',
        'ioc_type':   'ipv4-addr',
        'ioc_value':  '202.100.179.208',
        'confidence': 90,
        'severity':   'critical',
        'source':     'SSH_brute_force_log',
        'is_active':  1,
        'first_seen': now,
        'last_seen':  now,
        'country':    'CN',
        'tlp':        'GREEN',
        'tags':       'brute-force,ssh,malicious-activity',
        'description':'SSH brute force attacker observed in SSH_sample.log'
    },
    {
        'stix_id':    'indicator--ssh-brute-004',
        'ioc_type':   'ipv4-addr',
        'ioc_value':  '5.36.59.76',
        'confidence': 75,
        'severity':   'high',
        'source':     'SSH_brute_force_log',
        'is_active':  1,
        'first_seen': now,
        'last_seen':  now,
        'country':    'RU',
        'tlp':        'GREEN',
        'tags':       'brute-force,ssh,root-attempt',
        'description':'SSH root brute force attacker observed in SSH_sample.log'
    },
]

for ioc in iocs_to_insert:
    cursor.execute("""
        INSERT OR REPLACE INTO ioc_indicators
        (stix_id, ioc_type, ioc_value, confidence, severity, source,
         is_active, first_seen, last_seen, country, tlp, tags, description)
        VALUES
        (:stix_id, :ioc_type, :ioc_value, :confidence, :severity, :source,
         :is_active, :first_seen, :last_seen, :country, :tlp, :tags, :description)
    """, ioc)
    print(f"Inserted: {ioc['ioc_value']} | {ioc['severity']} | {ioc['country']}")

conn.commit()

print("\n=== Verifying insertion ===\n")
cursor.execute("SELECT COUNT(*) FROM ioc_indicators WHERE is_active=1")
print(f"Total active IOCs now: {cursor.fetchone()[0]}")

cursor.execute("""
    SELECT ioc_value, severity, confidence, country
    FROM ioc_indicators
    WHERE ioc_value IN ('173.234.31.186','52.80.34.196','202.100.179.208','5.36.59.76')
    AND is_active=1
""")
print("\nSSH IPs now in database:")
for row in cursor.fetchall():
    print(f"  {row[0]} | severity: {row[1]} | confidence: {row[2]} | country: {row[3]}")

conn.close()
print("\nDone! Your demo is ready.")