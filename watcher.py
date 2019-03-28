from web3 import Web3, HTTPProvider, IPCProvider, WebsocketProvider
from pysolcrypto.altbn128 import randsn, addmodp, asint
from pysolcrypto.schnorr import *
from pysolcrypto.curve import *
from pysolcrypto.utils import *
from eth_keys import keys

import datetime

import time
import json
import asyncio
import websockets
import plyvel

import logging

logging.basicConfig()

STATE = {'value': 0}
CLIENTS = {}
CONDITIONS = {}
DATASOURCE = {}

def state_event():
  return json.dumps({'type': 'state', **STATE})

def users_event():
  return json.dumps({'type': 'users', 'count': len(USERS)})

async def notify_state():
  if USERS:       # asyncio.wait doesn't accept an empty list
    message = state_event()
    await asyncio.wait([user.send(message) for user in USERS])

async def notify_users():
  if USERS:       # asyncio.wait doesn't accept an empty list
    message = users_event()
    await asyncio.wait([user.send(message) for user in USERS])
    
async def hello(client):
  message = json.dumps({'cmd_id':'hello'})
  await asyncio.wait(client.send(message))

async def bye(client):
  message = json.dumps({'cmd_id':'bye'})
  await client.send(message) 
  
async def register(address,client):
  global CLIENTS
  if address in DATASOURCE:
    message = json.dumps({'cmd_id':'registered'})
    CLIENTS[uid(client)] = {}
    CLIENTS[uid(client)]['socket'] = client
    CLIENTS[uid(client)]['address'] = address
    CLIENTS[uid(client)]['pubkey'] = myContract.functions.getPubkeyByAddress(address).call()
    CLIENTS[uid(client)]['handlers'] = {}
    CLIENTS[uid(client)]['handlers_data'] = {}
    CLIENTS[uid(client)]['handlers_id'] = 0
    CLIENTS[uid(client)]['condition'] = []
    for cond in DATASOURCE[address]:
      getConditionInfo(client,cond)
  else:
    message = json.dumps({'cmd_id':'unregistered'})
  await client.send(message)

async def unregister(address,client):
  try:
    del CLIENTS[address]
  except KeyError:
      print("Client not found")
  
async def send_data(websocket,save_data,msg,msg_type,handler_name):
  global CLIENTS
  cuid = uid(websocket)
  if (msg_type == 'Commit'):   
    CLIENTS[cuid]['handlers_id'] += 1
  CLIENTS[cuid]['handlers']['i_'+str(CLIENTS[cuid]['handlers_id'])+'_'+msg_type] = handler_name;
  CLIENTS[cuid]['handlers_data']['i_'+str(CLIENTS[cuid]['handlers_id'])+'_'+msg_type] = save_data; 
  #print('BEFORE', CLIENTS[cuid])
  message = json.dumps({'cmd_id':CLIENTS[cuid]['handlers_id'], 'type':msg_type, 'data':msg})
  await websocket.send(message)

async def _commit_handler(client,data,response):
  #global D,vl,vh
  try:
    D = makepoint(CLIENTS[uid(client)]['pubkey'])
    res = json.loads(response['data'])
    save_data = {}
    RD = stringtopoint(res['RD'])
    XD = stringtopoint(res['XD'])
    XW = data['XW']
    xW = data['xW']
    RW = data['RW']
    v = data['v']
    rW = data['rW']
    L = hashsn(D[0].n,D[1].n,XD[0].n,XD[1].n,XW[0].n,XW[1].n)
    HD = multiply(D,hashsn(L,D[0].n,D[1].n))
    HXD = multiply(XD,hashsn(L,XD[0].n,XD[1].n))
    hxw = mulmodn(xW,hashsn(L,XW[0].n,XW[1].n))
    HXW = sbmul(hxw)
    X = add(HD,add(HXD,HXW))
    R = add(RD,RW)
    save_data['Ccl'] = makepoint([0,0])
    save_data['Cch'] = makepoint([0,0])
    for cond in CLIENTS[uid(client)]['condition']:
      Y = cond['Y']
      if (cond['type'] == 1): #low  
        vl = cond['v']
        Cc = add(Y,HXW)
        Cc = negp(Cc)
        Cc = add(Cc,multiply(D,v-vl))
        save_data['Ccl'] = Cc
      elif (cond['type'] == 2): #high
        vh = cond['v']
        Cc = add(Y,HXW)
        Cc = add(Cc,multiply(D,vh-v))
        save_data['Cch'] = Cc
    save_data['X'] = X
    save_data['R'] = R
    save_data['XW'] = XW
    save_data['hxw'] = hxw   
    save_data['rW'] = rW
    save_data['XD'] = XD
    msg = json.dumps({'token':myToken,'Ccl':pointtostring(save_data['Ccl']),'Cch':pointtostring(save_data['Cch'])})
    await send_data(client,save_data,msg,'Sign','sign_handler')
  except Exception as e:
    print('asdf',e)

async def _sign_handler(client,data,response):
  #print('this is sign handler')
  try:
    #global D
    D = makepoint(CLIENTS[uid(client)]['pubkey'])
    res = json.loads(response['data'])
    sD = int(res['sD'],16)
    CD = stringtopoint(res['CD'])
    X = data['X']
    R = data['R']
    XD = data['XD']
    XW = data['XW']
    hxw = data['hxw']
    rW = data['rW']
    message = {'token':myToken,'CD':pointtostring(CD),'Ccl':pointtostring(data['Ccl']),'Cch':pointtostring(data['Cch']),'D':pointtostring(D),'XD':pointtostring(XD),'XW':pointtostring(XW)} 
    hm = bytes_to_int(keccak_256(json.dumps(message).encode('utf-8')).digest())     
    HXRM = hashsn(X[0].n,X[1].n,R[0].n,R[1].n,hm) # H(X,R,m)
    print('---------')
    print(message)
    print(X)
    print('---------')
    eW = mulmodn(HXRM,hxw) # H(X,R,m)H(L,XW)xW
    sW = addmodn(rW,eW)
    s = addmodn(sD,sW)
    proof = json.dumps({'message':message,'R':pointtostring(R),'s':hex(s)})
    print ("-----------Proof constructed at " + str(datetime.datetime.now()))
    #print(proof)
    await ask_device(proof)
  except Exception as e:
    print('fdsa',e)
  
handlers = {
    'commit_handler': _commit_handler,
    'sign_handler': _sign_handler,
}
 
async def evaluate(v,client):
  ok = 0
  for cond in CLIENTS[uid(client)]['condition']:
    if (cond['type']==1) and (cond['v']<=v): #low
      ok += 1
    elif (cond['type']==2) and (v<=cond['v']): #high
      ok += 1
    else:
      return
  if (ok==len(CLIENTS[uid(client)]['condition'])):
  #if (True):      
    print ("\n-----------Triggered at " + str(datetime.datetime.now()))
    xW = randsn()
    rW = randsn()
    XW = sbmul(xW)
    RW = sbmul(rW)
    msg = json.dumps({'XW':pointtostring(XW),'RW':pointtostring(RW)})
    save_data = {};
    save_data['XW'] = XW;
    save_data['xW'] = xW;
    save_data['RW'] = RW;
    save_data['rW'] = rW;
    save_data['v'] = v;
    await send_data(client,save_data,msg,'Commit','commit_handler')
    print('request sent')


async def listen(websocket, path):
  # register(websocket) sends user_event() to websocket
  try:
    #await websocket.send(state_event())
    async for message in websocket:
      #print('Received from data source: '+str(message))
      data = json.loads(message)
      cmd_id = data['cmd_id']
      if (cmd_id == 'hello'):
        client_address = data['address']
        await register(client_address,websocket)
      elif (cmd_id == 'val'):
        v = data['data']
        await evaluate(v, websocket)    
      else:
        global CLIENTS
        cuid = uid(websocket)
        #print('AFTER', CLIENTS[cuid])
        hdl = CLIENTS[cuid]['handlers']['i_'+str(data['cmd_id'])+'_'+data['type']];
        handler_data = CLIENTS[cuid]['handlers_data']['i_'+str(data['cmd_id'])+'_'+data['type']];
        await handlers[hdl](websocket,handler_data,data);
  finally:
      await unregister(uid(websocket),websocket)

async def ask_device(proof):
  async with websockets.connect(
          'ws://192.168.2.71:8765') as websocket:
      await websocket.send(proof)
      response = await websocket.recv()
      print(response)
      print ("-----------Finished at " + str(datetime.datetime.now()))
      
  

def getConditionInfo(client,cond):
  db = plyvel.DB('./node/watcher-db/', create_if_missing=True)                                                                       
  info = str(db.get(bytes(str(cond),'utf-8')),'utf-8')
  jsinfo = json.loads(info)
  v = jsinfo['value']*jsinfo['scale']
  t = jsinfo['type']
  y = int(jsinfo['bf'],16)
  Y = sbmul(y)
  condInfo = {'condhash': cond,'v':v,'type':t,'Y':Y}
  CLIENTS[uid(client)]['condition'].append(condInfo)
  db.close()

def uid(websocket):
  return websocket.remote_address[0]+':'+str(websocket.remote_address[1])

web3 = Web3(HTTPProvider('http://192.168.2.218:7545'))
contractAddress = "0x4FF6ded1234558A8d384CF868ABC390aaE04EC46"

with open("./node/ABI.json", 'r') as f:
     contract_abi = json.load(f)

myContract = web3.eth.contract(address=contractAddress, abi=contract_abi)
print(myContract)

myToken = 0x1989
db = plyvel.DB('./node/watcher-db/', create_if_missing=True)
condList = myContract.functions.getConditionsByToken(myToken).call()
for cond in condList:
  print(cond)
  datasource = myContract.functions.getDatasourceByCondition(cond).call()
  if datasource in DATASOURCE:
    DATASOURCE[datasource].append(cond)
  else:
    DATASOURCE[datasource] = []
    DATASOURCE[datasource].append(cond)
  
  
  print(db.get(bytes(str(cond),'utf-8')))
db.close()
print("ACTIVE DATASOURCE",DATASOURCE)
     
D = stringtopoint(('0x1318ac94213e5cfcefdadefd266e08b01eda47df5f196dad869e4a478a98c45d','0x81af4c964cb9d630a45c4470c0a9b0adceab66ae3cdbd0a090339b3d97b3b92')) 



asyncio.get_event_loop().run_until_complete(
    websockets.serve(listen, '192.168.2.71', 6789))
asyncio.get_event_loop().run_forever()



