import mysql.connector

def connectDB(dbName):
    try:
        conn =mysql.connector.connect(
            host="localhost",
            user="root",
            password="",
            database=dbName
        )
    except mysql.connector.Error as err:
        print(err)
        quit()

    return conn

