from Tools.clickjack.clickjack import *
from Tools.xss.xss import *
from Tools.mailMisconfig.mailmisconfig import mailmisconfig_check
from Tools.ssl_check.ssl import ssl_check

from db import connectDB
import mysql.connector
from Tools.xss.util.checker import *
from Tools.xss.util.parameterCrawl import *
from Tools.xss.util.urlparser import *
from Tools.xss.core import requester


def database(table_name):
    conn = connectDB('vulndescription')
    db = conn.cursor()

    db.execute("show tables")
    lst = db.fetchall()

    if not table_name in lst:
        try:
            sql = "CREATE TABLE %s (id INT AUTO_INCREMENT PRIMARY KEY, Vulnerability_name VARCHAR(255) DEFAULT NULL, vulnerable_urls LONGTEXT  DEFAULT NULL, severity VARCHAR(255) DEFAULT NULL)"% (table_name)
            db.execute(sql)
        except :
            pass

    conn.close()

def clickjacking(domain_name, table_name):
    conn = connectDB('vulndescription')
    db = conn.cursor()

    if clickjack_Check(domain_name):
        try:
            insert_sql = "INSERT INTO {} (Vulnerability_name, vulnerable_urls , severity) VALUES (%s, %s, %s)".format(table_name)
            val = ("Clickjacking", domain_name,"Low")
            db.execute(insert_sql, val)
            conn.commit()
            conn.close()

        except mysql.connector.errors.ProgrammingError as err:
            print(err)

    else:
        pass
    conn.close()


def mailmisconfig(domain_name, table_name):
    conn = connectDB('vulndescription')
    db = conn.cursor()

    if mailmisconfig_check(domain_name):
        try:
            insert_sql = "INSERT INTO {} (Vulnerability_name, vulnerable_urls , severity) VALUES (%s, %s, %s)".format(table_name)
            val = ("Mail misconfiguration", domain_name,"Low")
            db.execute(insert_sql, val)
            conn.commit()
            conn.close()

        except mysql.connector.errors.ProgrammingError as err:
            print(err)

    else:
        pass
    conn.close()


def sslcheck(domain_name, table_name):
    conn = connectDB('vulndescription')
    db = conn.cursor()

    if ssl_check(domain_name):
        try:
            insert_sql = "INSERT INTO {} (Vulnerability_name, vulnerable_urls , severity) VALUES (%s, %s, %s)".format(table_name)
            val = ("SSL Certificate missing", domain_name,"Low")
            db.execute(insert_sql, val)
            conn.commit()
            conn.close()

        except mysql.connector.errors.ProgrammingError as err:
            print(err)

    else:
        pass
    conn.close()

def XSS(domain_name, table_name):
    conn = connectDB('vulndescription')
    db = conn.cursor()

    # check_XSS(domain_name)

    query = "LOAD DATA INFILE 'C:/Users/Pratik/Desktop/Weber_BE_Project-main/main/Tools/xss/xssVuln_url.txt' INTO TABLE %s LINES TERMINATED BY '\n' (vulnerable_urls)" % (table_name)

    db.execute(query)


    conn.close()
    
def scanner(domain_name):
    table_name = "Userid_vulDetails"
    database(table_name) # create a table for user

    # check if clickjacking
    clickjacking(domain_name, table_name)

    # check if XSS
    # XSS(domain_name, table_name)

    # check mail misconfiguration
    # mailmisconfig_check(domain_name,table_name)

    # check SSL certificate missing or expired 

    


scanner("www.testphp.vulnweb.com")