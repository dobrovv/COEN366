import sqlite3
con = sqlite3.connect('database.db')

cur = con.cursor()
print ("SELECT * FROM Users")
a = cur.execute(f"SELECT * FROM Users")
for e in a.fetchall():
    print(e)
print()

print("SELECT * FROM UsersAuth")
a = cur.execute(f"SELECT * FROM UsersAuth")
for e in a.fetchall():
    print(e)
print()

# Save (commit) the changes
con.commit()

# We can also close the connection if we are done with it.
# Just be sure any changes have been committed or they will be lost.
con.close()


