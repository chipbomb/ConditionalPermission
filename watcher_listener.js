const EthCrypto = require('eth-crypto');
const Transaction = require('ethereumjs-tx');
const ethJsUtil = require('ethereumjs-util');
var Web3 = require('web3')
var ethers = require('ethers');
var level = require('level');
//var web3 = new Web3()

// connect to the local node
var web3 = new Web3(new Web3.providers.WebsocketProvider('ws://192.168.2.218:7545'));

var contractAddress = '0x4FF6ded1234558A8d384CF868ABC390aaE04EC46';
const myAddress = '0x7c28Bd7998B03a6Aeb516f35c448C76eDb3b7245';
const myPrivKey = '0x3edae5269e5ab4e3ec935e0ceed38865164e4869d929d04d3cb4c173ba7b02ac'

// Define the ABI (Application Binary Interface)
var fs = require('fs');
var ABI = JSON.parse(fs.readFileSync('ABI.json', 'utf8'));

// contract object
var contract = web3.eth.Contract(ABI, contractAddress);


//0xa774df989984c6ca4d7979116220719bb37500966aebe60aa11fb20b6d86a930
//0x793DFfF3a37AD0a60997fd4C3F86579176a96a16

/*{ address: '0x92D81D5d753B5fa433918FFBf3142Fb577E3DEf0', 0x1cd89ff2ef51d1887aab3fd7f78566e0b77477fd2d7abcb51d584b7e326e1ad4
  privateKey:
   '0xd8dc82d56bda6211a740af9346fa32642901d74c977aef75a3797095a323cbfc',
  publicKey:
   'ab0e7ab04bd08e9fa01f2042af4e4daf2d0a9612dbd0c5423105684cf23d989c255644d2c7ababac54842ef65e69f3663e9acfa62e65a26b77a2d369545b4c9f' }
{ address: '0x1de3522ec5EfEce5380AE8b78f8eD67EeBD0d84b', 0x4bab197d148e3799aa972b608054ec23f8b7145fc62a734feae535eb73925b
  privateKey:
   '0x86e2ff8e2a09ca7ffe380d985155134f19e4a7ac2828e1abdc666c033dae25b4',
  publicKey:
   '0e37c6fe4191ac3d3ec3375c4ba87ac76c3fad117184d2593b552ae54db9c5ae8f972cc5150e2d44864f2cd777876e39b3ac4bbb09bd3bbf5da62f0bb9d163df' }
   */

async function decrypt(sk,encrypted) {
  const encryptedObject = EthCrypto.cipher.parse(encrypted.substring(2));
  const decrypted = await EthCrypto.decryptWithPrivateKey(sk,encryptedObject);
  const decryptedPayload = JSON.parse(decrypted);
  //console.log('decrypted',decryptedPayload); 
  return decryptedPayload;
}

console.log('started')
contract.events.MessageRegistered({
    fromBlock: 0
}, (error, event) => {  })
.on('data', (event) => {
    console.log(ethers.utils.hexlify(ethers.utils.bigNumberify (event.returnValues.msg_hash))); // same results as the optional callback above
})
.on('changed', (event) => {
    // remove event from local database
})
.on('error', console.error);


contract.events.PermissionRegistered({
    fromBlock: 0
}, (error, event) => {  })
.on('data', (event) => {
  var holder = event.returnValues.holder;
  if (holder === myAddress) {
    var token = event.returnValues.token;
    var resource = event.returnValues.resource;
    var condHash = event.returnValues.cond;
    var db = level('./watcher-db', { valueEncoding: 'json' });
    db.get(condHash, async function (err, value) {
      if (err) {
        if (err.notFound) {
          var info = event.returnValues.info.split(":");
          console.log(info);
          var type = parseInt(info[0],10);
          var scale = parseInt(info[1],16);
          var decompressedInfo = EthCrypto.hex.decompress(info[2], true);
          var decrypted = await decrypt(myPrivKey,decompressedInfo);
          decrypted['type'] = type;
          decrypted['scale'] = scale;
          console.log('decrypted',decrypted);
          
          db.put(condHash, decrypted, function (err) {
            db.get(condHash, function (err, value) {
              console.log(value) // 42
              console.log(typeof value) // 'number'
            });    
            db.close();    
          });
          db.close();
          return
        }
      }
      db.close();
      console.log('already exist');
      console.log(condHash,typeof condHash);
      console.log(value);
    });
  }
   
})
.on('changed', (event) => {
    // remove event from local database
})
.on('error', console.error);




