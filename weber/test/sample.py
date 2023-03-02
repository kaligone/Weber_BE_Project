import mysql.connector
import json

mydb = mysql.connector.connect(
            host="localhost",
            user="root",
            password="",
            database="vulndescription"
)
mycursor = mydb.cursor()

# mycursor.execute("CREATE TABLE vul.json_data (id INT AUTO_INCREMENT PRIMARY KEY, data JSON)")

# data={"student":{ "name":"Harry", "country":"United State", "ContactNo":2545454 }}
# data=['http://testphp.vulnweb.com/hpp/params.php?p=%3Cimg+src%3Dx+onerror%3Dalert%281%29%3E&pp=%3Cimg+src%3Dx+onerror%3Dalert%281%29%3E', 'http://testphp.vulnweb.com/hpp/params.php?p=%3Cscript%3Ealert%281%29%3C%2Fscript%3E&pp=%3Cscript%3Ealert%281%29%3C%2Fscript%3E', 'http://testphp.vulnweb.com/listproducts.php?cat=%3Cimg+src%3Dx+onerror%3Dalert%281%29%3E', 'http://testphp.vulnweb.com/listproducts.php?cat=%3Cscript%3Ealert%281%29%3C%2Fscript%3E', 'http://testphp.vulnweb.com:80/listproducts.php?cat=%3Cimg+src%3Dx+onerror%3Dalert%281%29%3E', 'http://testphp.vulnweb.com:80/listproducts.php?cat=%3Cscript%3Ealert%281%29%3C%2Fscript%3E', 'http://testphp.vulnweb.com/listproducts.php?cat=%3Cimg+src%3Dx+onerror%3Dalert%281%29%3E&zfdfasdf=%3Cimg+src%3Dx+onerror%3Dalert%281%29%3E', 'http://testphp.vulnweb.com/listproducts.php?cat=%3Cscript%3Ealert%281%29%3C%2Fscript%3E&zfdfasdf=%3Cscript%3Ealert%281%29%3C%2Fscript%3E']
# Assuming your JSON data is stored in a Python dictionary called `data`
# print(type(data))
# y=len(data)
# index=[]
# for i in range(0,y):
#     index=index+[i]
# dictionary = {k: v for k, v in zip(index, data)}
# print(type(dictionary))
# json_data = json.dumps(dictionary)
# print(type(json_data))

# Insert the data into the table
# mycursor.execute("INSERT INTO vul.json_data (data) VALUES (%s)", (json_data,))
mycursor.execute("SELECT * FROM vulndescription.found_vulDetails")
result = mycursor.fetchall()
print(type(result))
# print(result[0][4])
abc=result[0][6]
# print(abc)
data = json.loads(abc)
print(data)

# Convert the JSON-formatted data into a dictionary
# data = json.loads(row[1])
for (k, v) in data.items():
    print("Key: " + k)
    print("Value: " + str(v))
#     # Process the data as needed
# print(data)

mydb.commit()
