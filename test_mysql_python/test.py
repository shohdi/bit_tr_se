import mysql.connector
import json
import numpy as np

cnx = mysql.connector.connect(user='shohdi', password='P@ssw0rd',
                              host='127.0.0.1',
                              database='forex_db')
cnx._open_connection()

cursor = cnx.cursor()


#cursor.execute('create table numpy(id int primary key , arr TEXT)')

a = np.random.rand(3,2)
print(a)
b = a.tolist()
b = json.dumps(b)


cursor.execute("insert into numpy (id,arr) VALUES (1,'"+b+"');")


#Fetching 1st row from the table
cursor.execute('select * from numpy;')
result = cursor.fetchall()
#print(result)
#print(len(result))
#print(result[0][1])
c = json.loads( result[0][1])
c = np.array(c,np.float)
print(c)

cnx.close()