
import mysql.connector
import json
import numpy as np
from shohdi_lib import MySqlHandler
import pickle
import base64
import ptan



class ShohdiExperienceReplayBuffer:
    def __init__(self, experience_source, buffer_size,name):

        assert isinstance(experience_source, (ptan.experience.ExperienceSource, type(None)))
        assert isinstance(buffer_size, int)
        self.experience_source_iter = None if experience_source is None else iter(experience_source)
        self.buffer = []
        self.capacity = buffer_size
        self.pos = 0
        self.pos_insert  = 0
        self.name = name
        self.myHandler = MySqlHandler.MySqlHandler(user='shohdi', password='P@ssw0rd',
                              host='127.0.0.1',
                              database='bitcoin')
        
        foundTable = self.myHandler.execute_query("SELECT * FROM information_schema.tables WHERE table_schema = '"+ self.myHandler.database +"' AND table_name = '"+ self.name + "' LIMIT 1")
        if len(foundTable) == 0:
            #create new table for the buffer
            self.myHandler.execute_non_query("CREATE TABLE "+ self.name  +" (   MyID INT NOT NULL AUTO_INCREMENT, MyObj TEXT NULL  ,   PRIMARY KEY (MyID) ) AUTO_INCREMENT = 1")
        




    def __len__(self):
        count = self.myHandler.execute_query("SELECT count(*) from " + self.name + " ")
        return int(count[0][0])

    def transformDbToObj(self,dbCol):
        if(dbCol is None or dbCol == ''):
            return None
        bytesCol = dbCol.encode('ascii')

        aicle = base64.b64decode(bytesCol)
        ret = pickle.loads(aicle)
        return ret
    
    def transformObjToDb(self,obj):
        if(obj is None):
            return ''
        aicle = pickle.dumps(obj)
        dbCol = base64.b64encode(aicle)
        strVal = dbCol.decode('ascii')
        
        return strVal

    def getArrayByQuery(self,query):
        ret = []
        result = self.myHandler.execute_query(query)
        for i in range(len(result)):
            obj = self.transformDbToObj(result[i][1])
            ret.append(obj)
        
        return ret


    def getOne(self,pos):
        dbArray = self.getArrayByQuery("select * from "+ self.name +" where MyID = '" + str(pos) + "' ")
        if(dbArray == None or len(dbArray) == 0):
            return None
        return dbArray[0]

        

    def __iter__(self):
        return self
    
    def __next__(self):
                
        ret = self.getOne(self.pos+1)
        self.pos = ((self.pos + 1) % self.__len__())


        return ret
    


    def sample(self, batch_size):
        """
        Get one random batch from experience replay
        TODO: implement sampling order policy
        :param batch_size:
        :return:
        """
        if self.__len__() <= batch_size:
            return self.getArrayByQuery("select * from "+ self.name +" ")
        # Warning: replace=False makes random.choice O(n)
        keys = np.random.choice(self.__len__(), batch_size, replace=True)
        return [self.getOne(key) for key in keys]

    def addOne(self,obj):
        dbValue = self.transformObjToDb(obj)
        
        self.myHandler.execute_non_query("insert into "+ self.name +" (MyObj) VALUES ('"+ dbValue +"') ")



    def updateOne (self,pos,obj):
        dbValue = self.transformObjToDb(obj)
        self.myHandler.execute_non_query(" update "+ self.name +" set MyObj = '" + dbValue + "' where MyID = '"+ str(pos) +"' ")


    def _add(self, sample):
        if self.__len__() < self.capacity:
            self.addOne(sample)
        else:
            self.updateOne( self.pos_insert + 1, sample)
            self.pos_insert = ((self.pos_insert + 1) % self.capacity)
        
        

    def populate(self, samples):
        """
        Populates samples into the buffer
        :param samples: how many samples to populate
        """
        for _ in range(samples):
            entry = next(self.experience_source_iter)
            self._add(entry)