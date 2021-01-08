from shohdi_lib.BitCoinLib import BitCoinLib
import numpy as np
import time as ts
from shohdi_lib.convert_binary import convert_binary
import collections





def main():
    while True :
        try:

            lib = BitCoinLib()
            address = "1PywDp1cSEtAabEMbYj4ptwXx6bMBpCuKD"
            coinbase_message = "Thanks allah for all this money".encode().hex()
            block_template = lib.rpc_getblocktemplate()
            height = block_template['height']
            
            
            test_height = lib.rpc("getblockcount")
            start_time = ts.time()
            extranonceArr = np.zeros(96,dtype=np.float32)
            nonce = np.random.randint(0xffffffff)

            lib.last_header = None
            i = 0
            historyArrInput = collections.deque([],maxlen=10000000)
            historyArrOutput = collections.deque([],maxlen=10000000)
            while True:
                i += 1
                extranonceArr = np.zeros(96,dtype=np.float32)
                for index in range(len(extranonceArr)):
                    extranonceArr[index] = np.random.randint(2)
                
                extranonce = lib.converter.fromBinToInt(extranonceArr)
           

                
                block_template,target_hash,extranonce,address,block_header = lib.calculateMerkleRoot(block_template,coinbase_message,address,extranonce)
        
                
                mined_block,block_hash,foundBetter = lib.createBlockHeader(block_template,block_header,nonce,target_hash)

                inputItem = lib.converter.fromEncodedStringToBin(block_hash)
                historyArrInput.append(inputItem[0:96])
                historyArrOutput.append(extranonceArr)

                if(foundBetter):
                    print ("extranonce " , extranonce)
                

                if (mined_block is not None):
                    print('solved !')
                    
                    submission = lib.block_make_submit(mined_block)
                    response = lib.rpc_submitblock(submission)
                    if response is not None:
                    
                        print("Submission Error: {}".format(response))
                    else:
                        print('Submitted ! ')
                    break


                if(extranonce % (10 ** 6) == 0):
                    test_height = lib.rpc("getblockcount")
                    if(test_height >= height):
                        
                        print('end of block ',height,' new height ' , test_height )
                        break
                    else:
                        print('block height ',height,' last height ' , test_height )
                    print('nonce : ' , nonce)
                    current_time = ts.time()
                    f_s = i/((current_time-start_time) * 1000 * 1000 )
                    print('hash rate : ',f_s,' MHash/s')


            
            


        except Exception as e:
            print(e)
            







if __name__ == "__main__":
    main()