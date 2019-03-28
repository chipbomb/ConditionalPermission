from web3 import Web3, HTTPProvider, IPCProvider, WebsocketProvider
from pysolcrypto.altbn128 import randsn, addmodp, asint
from pysolcrypto.schnorr import *
from pysolcrypto.curve import *
from pysolcrypto.utils import *

import time
import json
import asyncio
import websockets

print("hello")
web3 = Web3(HTTPProvider('http://192.168.2.218:7545'))
contractAddress = "0x4FF6ded1234558A8d384CF868ABC390aaE04EC46"

with open("./node/ABI.json", 'r') as f:
     contract_abi = json.load(f)
print("starting...")
myContract = web3.eth.contract(address=contractAddress, abi=contract_abi)
print(myContract)

async def hello(websocket, path):
    print("listening....")
    res = 'false'
    ok = 0
    message = await websocket.recv()
    print(message)
    m = json.loads(message)
    msg = m['message']
    R = stringtopoint(m['R'])
    s = int(m['s'],16)
    token = msg['token']
    CD = stringtopoint(msg['CD'])
    Ccl = stringtopoint(msg['Ccl'])
    Cch = stringtopoint(msg['Cch'])
    condList = myContract.functions.getConditionsByToken(token).call()
    D = stringtopoint(msg['D'])
    XD = stringtopoint(msg['XD'])
    XW = stringtopoint(msg['XW'])
    L = hashsn(D[0].n,D[1].n,XD[0].n,XD[1].n,XW[0].n,XW[1].n)
    HD = multiply(D,hashsn(L,D[0].n,D[1].n))
    HXD = multiply(XD,hashsn(L,XD[0].n,XD[1].n))
    HXW = multiply(XW,hashsn(L,XW[0].n,XW[1].n))
    X = add(HD,add(HXD,HXW))
    for cond in condList:
      data = myContract.functions.getCondtionCommitment(cond,token).call()
      C = myContract.functions.ExpandPoint(data[0]).call()
      C = makepoint(C)
      t = int(data[1][0],16)
      if (t==1): #low X = CD - (CL+Ccl)
        temp = add(C,Ccl)
        temp = negp(temp)
        temp = add(temp,CD)
        if (X[0].n==temp[0].n and X[1].n==temp[1].n):
          ok += 1
      if (t==2): #high X = CH+CD-Cch
        temp = negp(Cch)
        temp = add(CD,temp)
        temp = add(C,temp)
        if (X[0].n==temp[0].n and X[1].n==temp[1].n):
          ok += 1
    if (ok==len(condList)):
      print('Commitments ok')
      sG = sbmul(s)
      hm = bytes_to_int(keccak_256(json.dumps(msg).encode('utf-8')).digest())     
      HXRM = hashsn(X[0].n,X[1].n,R[0].n,R[1].n,hm) 
     # print('---------')
     # print(X)
     # print(m['message'])
     # print('---------')
      E = multiply(X,HXRM) # H(X,R,m)X
      sGp = add(R,E);

      if (sG[0].n==sGp[0].n and sG[1].n==sGp[1].n):
        #if (Ccl[0].n != 0 and Ccl[1].n != 0):
          
        res = 'true'
      else:
       res = 'false'
    print(res)
    await websocket.send(res)

start_server = websockets.serve(hello, '192.168.2.71', 8765)

asyncio.get_event_loop().run_until_complete(start_server)
asyncio.get_event_loop().run_forever()
