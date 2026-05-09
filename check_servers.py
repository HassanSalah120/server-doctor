import sqlite3
conn = sqlite3.connect('data/server_doctor.db')
conn.row_factory = sqlite3.Row
cursor = conn.cursor()
cursor.execute("SELECT id, name, username, CASE WHEN password IS NULL THEN 0 ELSE 1 END as has_pw, key_path FROM servers ORDER BY id DESC LIMIT 5")
rows = cursor.fetchall()
for r in rows:
    print(f"ID {r['id']}: {r['name']} | user={r['username']} | has_pw={r['has_pw']} | key={r['key_path']}")
conn.close()
