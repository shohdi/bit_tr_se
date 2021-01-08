import numpy as np

class convert_binary:
    def fromIntToBin(self,number):
        b = bin(number)
        b = b[2:]
        #print(b)
        arr = np.zeros((len(b),),dtype=np.float32)
        for i in range(len(b)):
            arr[i] = float(b[i])
        return arr

    def fromBinToInt(self,arr):
        b = self.convertArrayToString([str(int(arr[i]))[0] for i in range(len(arr))])
        #print(b)
        b = '0b' + b
        #print(b)
        c = int(b,2)
        return c
    
    def convertArrayToString(self,s): 
  
        # initialization of string to "" 
        new = "" 
    
        # traverse in the string  
        for x in s: 
            new += x  
    
        # return string  
        return new



    def fromStringToBin(self,s):
        encoded = s.encode('utf16')
        print (encoded)
        return self.fromEncodedStringToBin(encoded)

    def fromEncodedStringToBin(self,s):
        new = ""
        encoded = s
        for i in range(len(encoded)):
            b = bin(int(encoded[i]))
            b = b[2:]
            while len(b) < 8:
                b = '0' + b
            new = new + b
        arr = np.zeros((len(new),),dtype=np.float32)
        for i in range(len(new)):
            arr[i] = float(new[i])
        return arr
    
    def fromBinToEncoded(self,b):
        b = np.reshape(b,(-1,8))
        #print(b)
        new = []
        for i in range(b.shape[0]):
            #print(b[i])
            bt = self.fromBinToInt(b[i])
            #print(bt)
            new.append(bytes([bt]))
        #print(new)
        ret = b''.join(new)
        #print(ret)
        return ret
    
    def fromBinToString(self,b):
        en = self.fromBinToEncoded(b)
        print(en)
        str = en.decode('utf16')
        return str