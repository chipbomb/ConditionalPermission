const EthCrypto = require('eth-crypto');
var Web3 = require('web3')
var ethers = require('ethers');
var inquirer = require('inquirer');
var chalkPipe = require('chalk-pipe');
//var CryptoJS = require("crypto-js");
const Transaction = require('ethereumjs-tx');
const ethJsUtil = require('ethereumjs-util');
var level = require('level');

var web3 = new Web3(new Web3.providers.HttpProvider('http://35.9.42.169:7545'));
let provider = new ethers.providers.JsonRpcProvider('http://35.9.42.169:7545');

var contractAddress = '0x428AD7426C4F6076A26F10C59238B1945590f215'

// Define the ABI (Application Binary Interface)
var fs = require('fs');
var abi = JSON.parse(fs.readFileSync('ABI.json', 'utf8'));

// contract object
let contractweb3 = web3.eth.Contract(abi,contractAddress);
let contract = new ethers.Contract(contractAddress, abi, provider);
let privateKey = '0x03cb1ff2dac287870c5c5e4f23ac96327e2866b287368c2c7bd2057a8264f396';
let wallet = new ethers.Wallet(privateKey, provider);

/*const privateKey = '0x40622b90f09743f476534ee7b254b64dbc454917d4bc309e032c79aec2a9b7a8';
const account = web3.eth.accounts.privateKeyToAccount(privateKey);
web3.eth.accounts.wallet.add(account);
web3.eth.defaultAccount = account.address;*/

// Create a new instance of the Contract with a Signer, which allows
// update methods
let contractWithSigner = contract.connect(wallet);
// ... OR ...
// let contractWithSigner = new Contract(contractAddress, abi, wallet)

// "0xaf0068dcf728afa5accd02172867627da4e6f946dfb8174a7be31f01b11d5364"


var prompt_options = 
  {
    type: 'list',
    name: 'option',
    message: "Select option",
    choices: ['Register public key','Register message','Register condition','Register permission','Auto upload','Quit']
  };
  
var prompt_pubkey = [
  {
    type: 'input',
    name: 'address',
    message: 'Address'
  },
  {
    type: 'input',
    name: 'privkey',
    message: 'Private key (without 0x)'
  }
];

var prompt_message = [
  {
    type: 'input',
    name: 'message',
    message: 'Message'
  },
  {
    type: 'input',
    name: 'datasource',
    message: 'Datasource'
  }
];

var prompt_condition = [
  {
    type: 'number',
    name: 'value',
    message: 'Value'
  },
  {
    type: 'input',
    name: 'datasource',
    message: 'Datasource'
  }
];

var prompt_permission = [
  {
    type: 'input',
    name: 'holder',
    message: 'Holder',
    default: function() {
      return '0x7c28Bd7998B03a6Aeb516f35c448C76eDb3b7245';
    }
  },
  {
    type: 'input',
    name: 'resource',
    message: 'Resource',
    default: function() {
      return '0x6dD8f96Adce3A2b4F0dB819b20FaC52061F05a60';
    }
  },
  {
    type: 'input',
    name: 'condition',
    message: 'Condition',
    default: function() {
      return '0xf0a585586e9ce45521aa1be457502e4d7e09166b5e90314f2a46117d48690f90';
    }
  },
  {
    type: 'list',
    name: 'type',
    message: 'Type',
    choices: ['Low','High','None']
  },
  {
    type: 'number',
    name: 'scale',
    message: 'Scaling factor',
    when: function(answers) {
      return (answers.type !== 'None');
    }
  },
  {
    type:'input',
    name: 'token',
    message: 'Token'
  }
];

async function getPubkeyByAddress(address) {
  var filter = { addr: address};
  let events = await contractweb3.getPastEvents('PubkeyRegistered', { filter,fromBlock: 0,toBlock: 'latest'});
  var txHash = events[0].transactionHash;
  var tx = await web3.eth.getTransaction(txHash);
  const pk = new Transaction({
      nonce: tx.nonce,
      gasPrice: ethJsUtil.bufferToHex(new ethJsUtil.BN(tx.gasPrice)),
      gasLimit: tx.gas,
      to: tx.to,
      value: ethJsUtil.bufferToHex(new ethJsUtil.BN(tx.value)),
      data: tx.input,
      chainId: 5777,
      r: tx.r,
      s: tx.s,
      v: tx.v,
  }).getSenderPublicKey();
  return pk.toString('hex'); 
}

async function encrypt(payload, pubkey) {
  const encrypted =  await EthCrypto.encryptWithPublicKey(pubkey, JSON.stringify(payload));
  
  //console.log(encrypted)
  const encryptedString = EthCrypto.cipher.stringify(encrypted);
  //console.log(encryptedString);
  return encrypted;
}

async function registerPubkey(address,privkey) {
  let subwallet = new ethers.Wallet("0x"+privkey, provider);
  let subcontractWithSigner = contract.connect(subwallet);
  
  var r = ethers.utils.bigNumberify(ethers.utils.randomBytes(32));
  let key = await contract.getRandomPubKey(r);   
  console.log("pubkey",ethers.utils.hexlify(key[0][0]),ethers.utils.hexlify(key[0][1]));  
  await subcontractWithSigner.registerPubkey(address, key[0]).catch(error => { console.log('caught', error.message); });
  console.log("privkey",key[1]);
}

async function registerMessage(message,datasource) {
  var s = ethers.utils.bigNumberify(ethers.utils.randomBytes(32));
  let res = await contract.commitMessage(message, s);
  await contractWithSigner.registerMessage(res[0], datasource).catch(error => { console.log('caught', error.message); });
  console.log("Registered message ", message, " with secret ", ethers.utils.hexlify(res[2]));//  public view returns (uint256[2] memory msg_point, uint256 msg_hash, uint256 priv) 
  console.log("Message hash: ", ethers.utils.hexlify(res[1]));
}

async function registerCondition(v,datasource) {
  var s = ethers.utils.bigNumberify(ethers.utils.randomBytes(32));
  let res = await contract.commitCondition(v,s,datasource);
  var ok = 1;
    //public view returns (uint256 C, uint256 cond_hash)
  await contractWithSigner.registerCondition(res[0],res[1],datasource).catch(error => { ok = 0; console.log('caught', error.message); });
  if (ok) {
    var condHash = ethers.utils.hexlify(res[1]);
    var info = {value:v,bf:ethers.utils.hexlify(s)};
    var db = level('./my-db', { valueEncoding: 'json' });
    db.put(condHash, info, function (err) {
      db.get(condHash, function (err, value) {
        console.log(value) // 42
        console.log(typeof value) // 'number'
        db.close();
      });
      
    });
    console.log("Registered condition value ", v, " with secret ", ethers.utils.hexlify(s));
    console.log("Condition hash: ", condHash);
  }
  
}

async function registerPermission(holder,resource,condition,type,scale,token) { //registerPermission(address holder, address resource, uint256 cond, string memory info, uint256 token)
  var t = 0;
  if (type === 'Low') t = 1;
  if (type === 'High') t = 2;
  var db = level('./my-db', { valueEncoding: 'json' });
  var privInfo = await db.get(condition);
  if (privInfo.type == 'NotFoundError') {
    db.close();
    return;
  }
  var holderpk = await getPubkeyByAddress(holder);
  var temp1 = await encrypt(privInfo,holderpk);
  var temp2 = EthCrypto.cipher.stringify(temp1);
  const compressedInfo = EthCrypto.hex.compress(temp2, true); // compress to base64
  var info = t+':'+scale.toString(16)+':'+compressedInfo;
  console.log(info);
  //console.log(holderpk,compressedInfo);
  /*   
  var info = {'type':t,'scale':scale,'privInfo':compressedInfo};
  var sk = '0x3edae5269e5ab4e3ec935e0ceed38865164e4869d929d04d3cb4c173ba7b02ac';
  var decompressedInfo = EthCrypto.hex.decompress(compressedInfo, true);
  console.log('decopmressed',decompressedInfo.substring(2));
  const encryptedObject = EthCrypto.cipher.parse(decompressedInfo.substring(2));
  const decrypted = await EthCrypto.decryptWithPrivateKey(sk,encryptedObject);
  const decryptedPayload = JSON.parse(decrypted);
  console.log('decrypted',decryptedPayload);
  */
  db.close();
  await contractWithSigner.registerPermission(holder,resource,ethers.utils.bigNumberify(condition),info,ethers.utils.bigNumberify(token))
  .catch(error => { console.log('caught', error.message); });
}



async function main() {  
  //console.log(web3.utils.randomHex(32));
  console.log("Connected.");
  //console.log(prompt_options.choices);
  let option = "start";
  while (option !== "Quit") {
    if (option == "start") {
      let answer = await inquirer.prompt(prompt_options);
      option = answer.option;
      //console.log(option);
      //question = (answer == 'yay') ? "2" : "1";
    } 
    else if (option === prompt_options.choices[0]){ // register pubkey
      let answer = await inquirer.prompt(prompt_pubkey);
      await registerPubkey(answer.address,answer.privkey);
      option = "start";
    }
    else if (option === prompt_options.choices[1]){ // register message
      let answer = await inquirer.prompt(prompt_message);
      console.log(answer);
      message = JSON.stringify({'message':answer.message})
      await registerMessage(message,answer.datasource);
      option = "start";
    }
    else if (option === prompt_options.choices[2]) { // register condition
      let answer = await inquirer.prompt(prompt_condition);
      await registerCondition(answer.value,answer.datasource);
      option = "start";
    }
    else if (option === prompt_options.choices[3]) { // register permission 
      let answer = await inquirer.prompt(prompt_permission);
      console.log(answer);
      //let pk = await getPubkeyByAddress(answer.holder);
      //console.log('pk',pk);
      await registerPermission(answer.holder,answer.resource,answer.condition,answer.type,answer.scale,answer.token);
      
      option = "start";
    }
    else if (option === prompt_options.choices[4]) { // auto upload
      ADDRESS = ['0x7c28Bd7998B03a6Aeb516f35c448C76eDb3b7245',
                '0x6dD8f96Adce3A2b4F0dB819b20FaC52061F05a60',
                '0x409b925ceeCce1e0D56654967A2B1421Bcd80bA3',
                '0xa258668818dd3Eb57E2844443f0a04e0e44b2CAc',
                '0xe969F55ee587f2bCFda0F504e5Faf67A7cd04FBB'
                ];
      PRIV = [ '3edae5269e5ab4e3ec935e0ceed38865164e4869d929d04d3cb4c173ba7b02ac',
              'cdab56a5233e379d6a44d605679c73a82e6aaeb31aa1128ad2f6746954ed8362',
              'e622354976d82b13b47202bbeef6cb07b8eacd0277d14630d2120913def4a75a',
              '7da400bec224c0829ceb5373ff98f0c11911daeae2c30ecc0bb971c36facc3cf',
              'b7ccb65b4f217f84df0e457df18e28b4829de5673525f75ac9fe6bf9f79a7a7f'
             ];
      for (i = 0; i < ADDRESS.length; i++) { 
        await registerPubkey(ADDRESS[i],PRIV[i]);
      }
      
      await registerCondition(70,'0xe969F55ee587f2bCFda0F504e5Faf67A7cd04FBB');
      await registerCondition(100,'0xe969F55ee587f2bCFda0F504e5Faf67A7cd04FBB');
      await registerCondition(12345,'0xa258668818dd3Eb57E2844443f0a04e0e44b2CAc');
      
      //await registerPermission('0x7c28Bd7998B03a6Aeb516f35c448C76eDb3b7245','0x6dD8f96Adce3A2b4F0dB819b20FaC52061F05a60')
      option = "start";
    }
  }
  
  console.log("done");
  
}

main()
