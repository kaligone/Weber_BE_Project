from flask import *
from db import *
import os
from db import *
import mysql.connector

conn = connectDB('vulndescription') # connecting to the database 
db = conn.cursor()

table_name = "found_vuldetails"
userName="test"
DomainName="www.facebook.com"
# where User_Id={} and domain_name={}
try:
    insert_sql = "SELECT data FROM {} WHERE User_Id='{}' and domain_name='{}'".format(table_name,userName,DomainName)
    # print(insert_sql)
    db.execute(insert_sql)
    lst = db.fetchall()
    conn.commit()
    conn.close()
except mysql.connector.errors.ProgrammingError as err:
    print(err)


for line1 in lst:
    data = json.loads(line1[0])
    for (k, v) in data.items():
        print("Key: " + k)
        print("Value: " + str(v))



