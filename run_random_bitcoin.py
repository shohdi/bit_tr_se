from shohdi_lib.BitCoinLib import BitCoinLib
import numpy as np
import time as ts



def main():
    while True :
        try:

            lib = BitCoinLib()
            address = "1PywDp1cSEtAabEMbYj4ptwXx6bMBpCuKD"
            coinbase_message = "Thanks allah for all this money".encode().hex()
            block_template = lib.rpc_getblocktemplate()
            height = block_template['height']
            extranonce = np.random.randint(0xffffffff)

            block_template,target_hash,extranonce,address,block_header = lib.calculateMerkleRoot(block_template,coinbase_message,address,extranonce,0)

            test_height = lib.rpc("getblockcount")
            start_time = ts.time()
            for i in range(0xffffffff):
                nonce = i
                state,reward,mined_block = lib.createBlockHeader(block_template,block_header,nonce,target_hash,extranonce,address)
                if (mined_block is not None):
                    print('solved !')
                    
                    submission = lib.block_make_submit(mined_block)
                    response = lib.rpc_submitblock(submission)
                    if response is not None:
                    
                        print("Submission Error: {}".format(response))
                    else:
                        print('Submitted ! ')
                    break


                if(nonce % (10 ** 6) == 0):
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