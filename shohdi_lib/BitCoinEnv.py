import gym
import gym.spaces
from gym.utils import seeding
import enum
import numpy as np
from shohdi_lib.BitCoinLib import BitCoinLib
#from BitCoinLib import BitCoinLib
import time
import sys
import threading
import collections



class BitCoinEnv(gym.Env):
   
    def __init__(self,sendOnDone):
        self.submit_count = 0
        self.submit_recalc = 0
        self.last_actions = np.zeros(64)
        self.last_reward = 0.0
        self.bit_coin_lib = BitCoinLib()
        self.current_time =  time.time()
        self.time_out = 30
       
        self.block_template = self.bit_coin_lib.rpc_getblocktemplate()
        self.last_call_time = time.time()
        self.block_height = self.block_template['height']
        self.send_on_done = sendOnDone if sendOnDone is not None else True
        
        self.address = "1PywDp1cSEtAabEMbYj4ptwXx6bMBpCuKD"
        self.coinbase_message = "Thanks allah for all this money".encode().hex()

        

        
        self.action_space = gym.spaces.Discrete(n=len(self.last_actions))
        self.old_states = collections.deque([],10)

        self.stateLike = np.zeros(186)

        self.observation_space = gym.spaces.Box(low=-np.inf, high=np.inf, shape=self.stateLike.shape, dtype=np.float32)
        
        self.seed()

    def reset(self):
        # make selection of the instrument and it's offset. Then reset the state
        pass
        #self.last_actions = np.zeros(64)
        
        #self._state = np.zeros(186)
        #self.current_time =  time.time()
        #self.last_call_time = self.current_time - self.time_out
        
        

    def step(self, action_idx):
        done = False
        

        
        
        
        #apply action
        self.last_actions[action_idx] = (self.last_actions[action_idx] + 1)%2
        extranonce = self.bit_coin_lib.converter.fromBinToInt(self.last_actions[0:32])
        nonce = self.bit_coin_lib.converter.fromBinToInt(self.last_actions[32:64])

        (state,reward,mined_block) = self.bit_coin_lib.calculateHeaderHash(self.block_template, self.coinbase_message,  self.address,extranonce,nonce)
        while len(self.old_states) < 10:
            self.old_states.append(state)
        #get defference so it will not be accumlated
        reward = reward - self.last_reward
        self.last_reward = reward

        
        try:

            if mined_block:
                print("Submitting:", submission, "\n")
                self.submit_recalc = self.submit_recalc + 1
                self.submit_count = self.submit_count + 1
                
                submission = self.bit_coin_lib.block_make_submit(mined_block)
                response = self.bit_coin_lib.rpc_submitblock(submission)
                if response is not None:
                   
                    print("Submission Error: {}".format(response))
                else:
                    print ("submitted count {}".format(self.submit_count))
                    if self.submit_recalc == 2:
                        self.submit_recalc = 0
                        time.sleep(3600)
                    done = True
                    self.last_call_time = self.current_time - self.time_out
                    print("Solved a block! Block hash: {}".format(mined_block['hash']))
            

                   
        except :
            type, value, traceback = sys.exc_info()
            print("error" ,type,value,traceback)

        self.current_time = time.time()
        if (self.current_time - self.last_call_time) >= self.time_out:
            try :
                
                new_block_template = self.bit_coin_lib.rpc_getblocktemplate()
                self.last_call_time = time.time()
                new_height = new_block_template['height']
                done = True
                    
                self.block_template = new_block_template
                self.block_height = new_height
                    
                
            except:
                type, value, traceback = sys.exc_info()
                print("error" ,type,value,traceback)
        

        #copy from deque
        ret_state = np.array([x for x in self.old_states ])
        

        if done:
            self.last_reward = 0
            self.old_states = collections.deque([],10)
            
        
        if self.send_on_done and not done:
            reward = 0

        return ret_state,reward,done,None






    def render(self, mode='human', close=False):
        pass

    def close(self):
        pass

    def seed(self, seed=None):
        self.np_random, seed1 = seeding.np_random(seed)
        seed2 = seeding.hash_seed(seed1 + 1) % 2 ** 31
        return [seed1, seed2]

