import sqlite3
import sys

# Update server ID 2 with the correct password
CORRECT_PASSWORD = input("Enter the correct SSH password for root@116.203.83.176: ")

conn = sqlite3.connect('data/server_doctor.db')
cursor = conn.cursor()

# Update server ID 2 (the latest one - Hassan Salah23)
cursor.execute("UPDATE servers SET password = ? WHERE id = 2", (CORRECT_PASSWORD,))
conn.commit()

# Verify
cursor.execute("SELECT id, name, CASE WHEN password IS NULL THEN 0 ELSE 1 END as has_pw FROM servers WHERE id = 2")
row = cursor.fetchone()
print(f"\n✓ Server ID {row[0]} ({row[1]}): password updated (has_pw={row[2]})")

conn.close()
print("\nNow go to http://127.0.0.1:8000/jobs and click the server to scan again.")
