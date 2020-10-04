import sqlite3

def create_DB():
	count=0
	conn = sqlite3.connect("test.db", detect_types=sqlite3.PARSE_DECLTYPES)
	c = conn.cursor()
	with open ("script.sql","r") as f:
		c.executescript(f.read())
		f.close()

	conn.commit()
	conn.close()

create_DB()