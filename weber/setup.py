import mysql.connector
import time
import re

def database():
    try:
        conn =mysql.connector.connect(
            host="localhost",
            user="root",
            password=""
        )
    except mysql.connector.Error as err:
        print(err)
        quit()

    db_name = "credential"
    db = conn.cursor()
    db.execute("show databases")
    lst = db.fetchall()

    # check if database exits
    if not db_name in lst:
        try:
            db.execute("create database {}".format(db_name))
            print("Database created...")
        except:
            pass
    else:
        try:
            conn =mysql.connector.connect(
                host="localhost",
                user="root",
                password="",
                database=db_name
            )
        except mysql.connector.Error as err:
            print(err)
            quit()

        db = conn.cursor()

    print(db)


def setup():
    db_name = "credential"
    try:
        conn =mysql.connector.connect(
            host="localhost",
            user="root",
            password="",
            database=db_name
        )
    except mysql.connector.Error as err:
        print(err)
        quit()
    
    db = conn.cursor()

    userName = input("Enter username : ")
    email = input("Enter the email : ")
    password_validation_case = "Password must follow the following condition : Minimum 8 characters.The alphabet must be between [a-z]At least one alphabet should be of Upper Case [A-Z]At least 1 number or digit between [0-9].At least 1 character from [ _ or @ or $ ]."
    while True:
        password = input("Enter the password : ")
        if (len(password)<=8):
            print(password_validation_case)
            continue
        elif not re.search("[a-z]", password):
            print(password_validation_case)
            continue
        elif not re.search("[A-Z]", password):
            print(password_validation_case)
            continue
        elif not re.search("[0-9]", password):
            print(password_validation_case)
            continue
        elif not re.search("[_@$]" , password):
            print(password_validation_case)
            continue
        elif re.search("\s" , password):
            print(password_validation_case)
            continue
        else:
            break

    table_name="userProfiles"
        
    db.execute("show tables")
    lst = db.fetchall()

    # create table if not created
    sql = "CREATE TABLE users (id INT AUTO_INCREMENT PRIMARY KEY,userName VARCHAR(255) DEFAULT NULL, email VARCHAR(255) UNIQUE KEY DEFAULT NULL, password VARCHAR(255) DEFAULT NULL)"
    if not table_name in lst:
        try:
            db.execute(sql)
        except:
            pass

    # insert data
    insert_sql = '''INSERT INTO users (userName, email, password) VALUES (%s, %s, %s)'''
    val = (userName, email, password)
    db.execute(insert_sql, val)
    conn.commit()
    conn.close()


    
        
def main():
    print("Welcome to the setup of weber : A web application scanner\n")
    print("Improve your web application security with weber web application scanner\n")
    ans = input("Start setup process (y/n) >>>> ")

    if ans=='n':
        quit()
    elif ans=='y':
        print("Starting the process to setup the weber...",end=" ")
        print("It will take some time to setup ...")
        # for i in range(10):
        #     print("##########",end="")
        #     time.sleep(5)
        database()
        setup()
        print("Setup is succesfully completed !! ")
        print(" Run the main.py file to access weber")

    else:
        quit()
        


if __name__=="__main__":
    main()