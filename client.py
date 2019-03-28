import asyncio
import websockets
from pysolcrypto.altbn128 import randsn, addmodp, asint
from pysolcrypto.schnorr import *
from pysolcrypto.curve import *
from pysolcrypto.utils import *
from sha3 import keccak_256
import time
import random
import json
import logging

import websockets
import asyncio

class WebSocketDatasource():

    def __init__(self,address,v,D,d):
        self.v = 0
        self.d = d
        self.D = D
        self.address = address
        self.HANDLER_DATA = {}

    async def connect(self):
        '''
            Connecting to webSocket server

            websockets.client.connect returns a WebSocketClientProtocol, which is used to send and receive messages
        '''
        self.connection = await websockets.client.connect('ws://192.168.2.71:6789')
        if self.connection.open:          
            # Send greeting
            await self.sendMessage(json.dumps({'cmd_id':'hello','address':self.address}))
            message = await self.connection.recv()
            print('Connection stablished. Client correcly connected')
            print(message)
            return self.connection

    async def sendData(self,msg_data,msg_type,cmd_id):
        msg = json.dumps({'cmd_id':cmd_id, 'type':msg_type, 'data':msg_data})
        await self.sendMessage(msg)

    async def processCommitMessage(self,commit_data,cmd_id):
      try:         
            RW = stringtopoint(commit_data['RW'])
            XW = stringtopoint(commit_data['XW'])
            xD = randsn()
            rD = randsn()
            XD = sbmul(xD)
            RD = sbmul(rD)
            msg_data = json.dumps({'XD':pointtostring(XD),'RD':pointtostring(RD)})
            save_data = {};
            save_data['XW'] = XW
            save_data['XD'] = XD
            save_data['xD'] = xD
            save_data['rD'] = rD
            save_data['RD'] = RD
            save_data['RW'] = RW
            self.HANDLER_DATA['i_'+str(cmd_id)+'_'+'Sign'] = save_data
            await self.sendData(msg_data,'Commit',cmd_id)
            #print('processed')
      except Exception as e:
            print(e)

    async def processSignMessage(self,data,cmd_id):
      try:
        save_data = self.HANDLER_DATA['i_'+str(cmd_id)+'_'+'Sign']
        Ccl = stringtopoint(data['Ccl'])
        Cch = stringtopoint(data['Cch'])
        v = self.v
        D = self.D
        d = self.d
        XD = save_data['XD']
        XW = save_data['XW'] 
        xD = save_data['xD'] 
        rD = save_data['rD'] 
        RD = save_data['RD'] 
        RW = save_data['RW'] 
        L = hashsn(D[0].n,D[1].n,XD[0].n,XD[1].n,XW[0].n,XW[1].n)
        hd = mulmodn(hashsn(L,D[0].n,D[1].n),d) # H(L,D)d
        HD = sbmul(hd)
        hxd = mulmodn(hashsn(L,XD[0].n,XD[1].n),xD) # H(L,XD)xD
        HXD = sbmul(hxd)
        HXW = multiply(XW,hashsn(L,XW[0].n,XW[1].n))
        X = add(HD,add(HXD,HXW))
        R = add(RD,RW)
        CD = add(multiply(D,v),HD)
        CD = add(CD,HXD)
        message = json.dumps({'token':data['token'],'CD':pointtostring(CD),'Ccl':pointtostring(Ccl),'Cch':pointtostring(Cch),'D':pointtostring(D),'XD':pointtostring(XD),'XW':pointtostring(XW)})
        hm = bytes_to_int(keccak_256(message.encode('utf-8')).digest())       
        HXRM = hashsn(X[0].n,X[1].n,R[0].n,R[1].n,hm) # H(X,R,m)
        print('---------')
        print(message)
        print(X)
        print('---------')
        eD = mulmodn(HXRM,addmodn(hd,hxd))
        sD = addmodn(rD,eD)
        msg_data = json.dumps({'CD':pointtostring(CD),'sD':hex(sD)})
        del self.HANDLER_DATA['i_'+str(cmd_id)+'_'+'Sign']
        await self.sendData(msg_data,'Sign',cmd_id)
        
      except Exception as e:
        print(e)

    async def sendMessage(self, message):
        '''
            Sending message to webSocket server
        '''
        await self.connection.send(message)

    async def receiveMessage(self, connection):
        '''
            Receiving all server messages and handling them
        '''
        while True:
            try:
                message = await connection.recv()
                #print('Received message from server: ' + str(message))
                msg = json.loads(message)
                cmd_id = msg['cmd_id']
                if (cmd_id == 'hello'):
                  print('registered')
                  continue
                msg_type = msg['type']                
                if (msg_type=="Commit"):
                  print('received commit request')
                  data = json.loads(msg['data'])
                  try:
                    await self.processCommitMessage(data,cmd_id)
                  except Exception as e:
                    print(e)
                if (msg_type=="Sign"):
                  print('received sign request')
                  data = json.loads(msg['data'])
                  try:
                    await self.processSignMessage(data,cmd_id)
                  except Exception as e:
                    print(e)
                  
            except websockets.exceptions.ConnectionClosed:
                print('Connection with server closed')
                break



    async def publishData(self, connection):
        '''
        Sending heartbeat to server every 5 seconds
        Ping - pong messages to verify connection is alive
        '''
        while True:
            try:
                self.v = random.randrange(60,110)
                message = json.dumps({'cmd_id':'val', 'data':self.v})
                print(message)
                await self.sendMessage(message)
                await asyncio.sleep(10)
            except websockets.exceptions.ConnectionClosed:
                print('Connection with server closed')
                break

    
    

    
                      
                
if __name__ == '__main__':
#    pubkey 0x2e877249c0aa2fb1067c70fb8f7ffe764ad3c60e518c2983422bfe149772b1be 0x286ece7594a25f83ce4e22c56cda02d3196daa791310432ea5ad5cdf645c2afc
#privkey BigNumber {
#  _hex:
#   '0x2d3fdde7e1f1a6b72932d0754bfc7c5ff30490425e0363de39375e6b6edb8fb4' }
#pubkey 0x2cc9c3696278e8a0d4a0a16fa3583c56106d1751a315906cd89169338cecaaea 0x21a08a1dcdcffe91367e818fa95d42f8f6457566888fd1675816eb68cb240072
#privkey BigNumber {
#  _hex:
#   '0x142ad6f325daedd4f17e65ea058dae606a857b8b6ced70e1f9b420fdded41e12' }
#pubkey 0x01b2ad0c1bb80b009546f0aa8e9cb72606743086a466933f32f5252403689e78 0x0febbb54e693817872e853cd8738cd8b31fba3a44636978f8adc6cadcf23a988
#privkey BigNumber {
#  _hex:
#   '0x0a21aadc2938e7c6c3037d2220c7b50795c03d08446b72fb04e981f134e514c1' }
#pubkey 0x044828ee07291040239e3022c428f2000ec530786895f59d852486d882f51d1b 0xa23830196504f1faf70e11a72d2d8bd1c3c897b170efdf9710ab4f6387a488
#privkey BigNumber {
#  _hex:
#   '0x2249371e88673ba602fa9633e4180853ad54665b2a72cec552f74dc0d52d8aa6' }
#pubkey 0x06bb84c003a5da273576970e53128c436ce0c0f9dda75edf6085358c6d753c01 0x21396b21826d12ea0a78e35c1437b97f4ff7ac5d3096a720e71a038c73626f58
#privkey BigNumber {
#  _hex:
#   '0x0c0ba43686fe9b0d73a4db045981d349698d02db0689a787786d89d781c1fee1' }


    D = stringtopoint(('0x06bb84c003a5da273576970e53128c436ce0c0f9dda75edf6085358c6d753c01','0x21396b21826d12ea0a78e35c1437b97f4ff7ac5d3096a720e71a038c73626f58'))
    d = 0x0c0ba43686fe9b0d73a4db045981d349698d02db0689a787786d89d781c1fee1
    client = WebSocketDatasource('0xe969F55ee587f2bCFda0F504e5Faf67A7cd04FBB',0,D,d)
    loop = asyncio.get_event_loop()
    # Start connection and get client connection protocol
    connection = loop.run_until_complete(client.connect())
    # Start listener and heartbeat 
    tasks = [
        asyncio.ensure_future(client.publishData(connection)),
        asyncio.ensure_future(client.receiveMessage(connection)),
    ]

    loop.run_until_complete(asyncio.wait(tasks))

   
  
