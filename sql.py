import sqlite3
import os
import hashlib

# This class is a simple handler for all of our SQL database actions
# Practicing a good separation of concerns, we should only ever call 
# These functions from our models

# If you notice anything out of place here, consider it to your advantage and don't spoil the surprise

class SQLDatabase():
    '''
        Our SQL Database

    '''

    # Get the database running
    def __init__(self, database_arg=":memory:"):
        self.conn = sqlite3.connect(database_arg)
        self.cur = self.conn.cursor()
        self.setup = False

    # SQLite 3 does not natively support multiple commands in a single statement
    # Using this handler restores this functionality
    # This only returns the output of the last command
    def execute(self, sql_string):
        out = self.cur.execute(sql_string)

    # Commit changes to the database
    def commit(self):
        self.conn.commit()

    #-----------------------------------------------------------------------------
    
    # Sets up the database
    # Default admin password
    def database_setup(self, admin_password='admin'):

        # Clear the database if needed
        if not self.setup:
            self.execute("DROP TABLE IF EXISTS Users")
            self.commit()

            # Create the users table
            self.execute("""CREATE TABLE Users(
                username TEXT UNIQUE,
                salt TEXT,
                password TEXT,
                admin INTEGER DEFAULT 0
            )""")

            self.commit()

            # Add our admin user
            self.add_user('admin', admin_password, 1)
            self.setup = True

    #-----------------------------------------------------------------------------
    # User handling
    #-----------------------------------------------------------------------------

    # Add a user to the database
    def add_user(self, username1, password, admin1=0):

        rand_salt = os.urandom(32)

        key = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        rand_salt,
        100000
        )
        sql_cmd = "INSERT INTO Users VALUES('{username}', '{salt}', '{password}', {admin})"
        sql_cmd = sql_cmd.format(username=username1, salt=rand_salt.hex(), password=key.hex(), admin=admin1)
        self.execute(sql_cmd)
        self.commit()
        return True

    #-----------------------------------------------------------------------------

    # Check login credentials
    def check_credentials(self, username1, password):
        get_query = "SELECT * FROM Users WHERE username = '{username}'"

        get_query = get_query.format(username=username1)
        self.execute(get_query)
        result = self.cur.fetchone()
        pw = ""
        salt = ""
        if result:
            salt = bytes.fromhex(result[1])
            pw = result[2]

            hashed_pw = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
            hashed_pw = hashed_pw.hex()
            print(pw)
            print(hashed_pw)
        # see if they match
            return (pw == hashed_pw)
        return False

# QUICK TEST (WORKING)
#db = SQLDatabase()
#db.database_setup()

#db.add_user('bob', 'booop', 0)
#print(db.check_credentials('bob', 'booop'))

