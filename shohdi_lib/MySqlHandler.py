import mysql.connector

class MySqlHandler:
    def __init__(self,user,password,host,database):
        self.user = user
        self.password = password
        self.host = host
        self.database = database

    


    def execute_non_query(self,query):
        cnx = mysql.connector.connect(user=self.user, password=self.password,
                              host=self.host,
                              database=self.database)
        
        try:

            cnx._open_connection()

            cursor = cnx.cursor()

            cursor.execute(query)
        except:
            None
        
        try:
            cnx.close()
        except:
            None



    def execute_query(self,query):
        cnx = mysql.connector.connect(user=self.user, password=self.password,
                              host=self.host,
                              database=self.database)
        result = None 
        try:

            cnx._open_connection()

            cursor = cnx.cursor()

            cursor.execute(query)
            result = cursor.fetchall()
        except:
            None
        
        try:
            cnx.close()
        except:
            None
        

        return result
