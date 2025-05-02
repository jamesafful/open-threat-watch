import sqlite3

conn = sqlite3.connect("data/cves.db")
cursor = conn.cursor()

cursor.execute('''
CREATE TABLE IF NOT EXISTS cves (
    cve_id TEXT PRIMARY KEY,
    published_date TEXT,
    last_modified_date TEXT,
    description TEXT,
    severity TEXT,
    cvss_score REAL
)
''')

conn.commit()
conn.close()

print("Database and table created successfully.")
