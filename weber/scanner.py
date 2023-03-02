from Tools.clickjack.clickjack import *
from Tools.xss.xss import *
from Tools.ssl_check.ssl import ssl_check

from db import connectDB
import mysql.connector
from Tools.xss.util.checker import *
from Tools.xss.util.parameterCrawl import *
from Tools.xss.util.urlparser import *
from Tools.xss.core import requester
from Tools.security_header.security_header import security_header_main
from Tools.mailMisconfig.Mail_Mis_Config import mail_mis_config
import json
from datetime import datetime




def database(table_name):
    conn = connectDB('vulndescription')
    db = conn.cursor()

    db.execute("show tables")
    lst = db.fetchall()

    if not table_name in lst:
        try:
            sql = "CREATE TABLE %s (id INT AUTO_INCREMENT PRIMARY KEY, User_Id VARCHAR(10) ,Vulnerability_name VARCHAR(255) DEFAULT NULL, domain_name LONGTEXT  DEFAULT NULL, severity VARCHAR(255) DEFAULT NULL,data JSON,last_time VARCHAR(50))"% (table_name)
            db.execute(sql)
        except :
            pass

    conn.close()

def clickjacking(domain_name, table_name,user_name,current_time):
    conn = connectDB('vulndescription')
    db = conn.cursor()
    url="http://"+domain_name
    parse_url = urlparse(url)
    domain=parse_url.netloc
    if domain.startswith('www.'):
        domain_name = domain[4:]
    print(domain_name)
    status=clickjack_Check(domain_name)
    domain_name="www."+domain_name
    try:
        #status true means vulnerable
        data={"clickjacking":status}
        json_data=json.dumps(data)
        insert_sql = "INSERT INTO {} (User_Id,Vulnerability_name, domain_name , severity,data,last_time) VALUES (%s, %s, %s, %s,%s,%s)".format(table_name)
        val = (user_name,"Clickjacking", domain_name,"Low",json_data,current_time)
        db.execute(insert_sql, val)
        conn.commit()
        conn.close()

    except mysql.connector.errors.ProgrammingError as err:
        print(err)
    conn.close()


def mailmisconfig(domain_name, table_name,user_name,current_time):
    conn = connectDB('vulndescription')
    db = conn.cursor()
    mmcf_data= mail_mis_config(domain_name)
    print(mmcf_data)
    if mmcf_data:
        try:
            json_data=json.dumps(mmcf_data)
            insert_sql = "INSERT INTO {} (User_Id,Vulnerability_name, domain_name , severity,data,last_time) VALUES (%s,%s, %s, %s,%s,%s)".format(table_name)
            val = (user_name,"Mail misconfiguration Record", domain_name,"Medium",json_data,current_time)
            db.execute(insert_sql, val)
            conn.commit()
            conn.close()

        except mysql.connector.errors.ProgrammingError as err:
            print(err)

    else:
        pass
    conn.close()


def sslcheck(domain_name, table_name,user_name,current_time):
    conn = connectDB('vulndescription')
    db = conn.cursor()
    cert_info=ssl_check(domain_name)
    print(cert_info)
    if cert_info:
        json_cert_info=json.dumps(cert_info)
        try:
            insert_sql = "INSERT INTO {} (User_Id,Vulnerability_name, domain_name , severity,data,last_time) VALUES (%s,%s, %s, %s,%s,%s)".format(table_name)
            val = (user_name,"SSL Certificate", domain_name,"High",json_cert_info,current_time)
            db.execute(insert_sql, val)
            conn.commit()
            conn.close()

        except mysql.connector.errors.ProgrammingError as err:
            print(err)

    else:
        pass

def XSS(domain_name, table_name,user_name,current_time):
    conn = connectDB('vulndescription')
    db = conn.cursor()

    xss_vulnerable_urls=check_XSS(domain_name)
    y=len(xss_vulnerable_urls)
    index=[]
    if y==0:
        xss_vulnerable_urls_validate = {0:""}
    else:
        for i in range(0,y):
            index=index+[i]
        xss_vulnerable_urls_validate = {k: v for k, v in zip(index, xss_vulnerable_urls)}

    json_data_xss = json.dumps(xss_vulnerable_urls_validate)
    insert_sql = "INSERT INTO {} (User_Id,Vulnerability_name, domain_name ,severity, data,last_time) VALUES (%s,%s, %s, %s,%s,%s)".format(table_name)
    val = (user_name,"Cross Site Scripting", domain_name,"High",json_data_xss,current_time)
    db.execute(insert_sql, val)
    conn.commit()
    conn.close()

def Security_Header_Scanner(domain_name,table_name,user_name,current_time):
    conn = connectDB('vulndescription')
    db = conn.cursor()
    url="http://"+domain_name
    try:
        data_information=security_header_main(url)
    except Exception as e:
        data_information="Max retries exceeded with url and Failed to establish a new connection Try After Some time"
        print(e)
    json_data_header = json.dumps(data_information)
    insert_sql = "INSERT INTO {} (User_Id,Vulnerability_name, domain_name , severity,data,last_time) VALUES (%s,%s, %s, %s,%s,%s)".format(table_name)
    val = (user_name,"Security_header", domain_name,"High",json_data_header,current_time)
    db.execute(insert_sql, val)
    conn.commit()
    conn.close()


    
def scanner(domain_name,user_name,current_time):
    table_name = "found_vulDetails"

    database(table_name) # create a table for user

    # check if clickjacking
    clickjacking(domain_name, table_name,user_name,current_time)

    # check mail misconfiguration
    mailmisconfig(domain_name,table_name,user_name,current_time)

    # check SSL certificate missing or expired 
    sslcheck(domain_name, table_name,user_name,current_time)
    
    # check for Security header
    Security_Header_Scanner(domain_name,table_name,user_name,current_time)

    # check if XSS
    XSS(domain_name, table_name,user_name,current_time)


scanner("www.pce.ac.in","test","tuesday")



