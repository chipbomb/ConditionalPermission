pragma solidity ^0.5.0;

contract manager {
  constructor() public {
    G1[0] = 1;
    G1[1] = 2;
    H = HashPoint(G1);
  }

  uint256[2] public G1;
  uint256[2] public H;
  uint256 constant public N = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;
  uint256 constant public P = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47;

  //Used for Point Compression/Decompression
  uint256 constant public ECSignMask = 0x8000000000000000000000000000000000000000000000000000000000000000;
  uint256 constant public a = 0xc19139cb84c680a6e14116da060561765e05aa45a1c72a34f082305b61f3f52; // (p+1)/4

  struct Message {
    uint id;
    //uint256 msg_hash;
    uint256 px;
    uint256 py;
    address datasource;
    //address watcher;
  }
  uint public messageCount;
  uint256[] MessageHash;
  mapping (uint256 => Message) public messages;
  event MessageRegistered(uint256 msg_hash, address datasource);

  function messageExist(uint256 msg_hash) public view returns (bool msgExist) {
       if (MessageHash.length == 0)
           return false;
       return (MessageHash[messages[msg_hash].id] == msg_hash);
   }

  function getMessageHash() public view returns (uint256[] memory ) {
    return MessageHash;
  }

  function commitMessage(string memory message, uint256 secret) public view returns (uint256[2] memory msg_point, uint256 msg_hash, uint256 priv) {
    require(bytes(message).length > 0);
    msg_point = ecMul(G1, uint256(keccak256(abi.encodePacked(secret, message))));
    msg_hash = uint256(keccak256(abi.encodePacked(msg_point[0], msg_point[1])));
    priv = uint256(keccak256(abi.encodePacked(secret, message)));
  }

  function registerMessage(uint256[2] memory msg_point, address datasource) public {
    uint256 msg_hash = uint256(keccak256(abi.encodePacked(msg_point[0], msg_point[1])));
    require(!messageExist(msg_hash));
    MessageHash.push(msg_hash);
    messages[msg_hash].px = msg_point[0];
    messages[msg_hash].py = msg_point[1];
    messages[msg_hash].datasource = datasource;
    messageCount++;
    emit MessageRegistered(msg_hash, datasource);
  }

  struct Condition {
    //uint256 Clow;
    //uint256 Chigh;
    uint256 C;
    address owner;
    address datasource; // compressed point
    uint id;
  }
  uint256[] ConditionHash;
  uint public conditionCount;
  mapping (uint256 => Condition) public conditions;
  event ConditionRegistered(uint256 cond_hash);

  struct PermissionData {
    uint256 condHash;
    string info;
  }

  struct Permission {
    address holder;
    address resource;
    PermissionData[] data;
  }
  mapping (uint256 => Permission) public Tokens;
  mapping (address => uint256[2]) public Pubkeys;
  event PermissionRegistered(address holder, address resource, uint256 cond, string info, uint256 token);
  event PubkeyRegistered(address indexed addr);
  function registerPubkey(address addr, uint256[2] memory pub) public {
    require(Pubkeys[addr][0] == uint256(0));
    Pubkeys[addr][0] = pub[0];
    Pubkeys[addr][1] = pub[1];
    //success = true;
    emit PubkeyRegistered(addr);
  }

  function getPubkeyByAddress(address addr) public view returns (uint256[2] memory pubkey) {
    pubkey = Pubkeys[addr];
  }

  function registerPermission(address holder, address resource, uint256 cond, string memory info, uint256 token) public {
    require(holder != address(0));
    require(resource != address(0));
    require(token != uint256(0));
    require(Tokens[token].holder == address(0)); // token must not exist stylesheet
    Tokens[token].holder = holder;
    Tokens[token].resource = resource;
    PermissionData memory p;
    p.condHash = cond;
    p.info = info;
    Tokens[token].data.push(p);
    emit PermissionRegistered(holder,resource,cond,info,token);
  }

  function getConditionsByToken(uint256 token) public view returns (uint256[] memory) {
    uint size;
    size = Tokens[token].data.length;
    uint256[] memory conds = new uint256[](size);
    for (uint i=0; i<size; i++) {
      conds[i] = Tokens[token].data[i].condHash;
    }
    return conds;
  }

  function getDatasourceByCondition(uint256 condhash) public view returns (address addr) {
    addr = conditions[condhash].datasource;
  }

  function getCondtionCommitment(uint256 condhash, uint256 token) public view returns (uint256 c, string memory info) {
    c = conditions[condhash].C;
    for (uint i=0; i<Tokens[token].data.length; i++) {
      if (condhash == Tokens[token].data[i].condHash)
        info = Tokens[token].data[i].info;
        break;
    }
  }

  function conditionExist(uint256 cond_hash) public view returns (bool condExist) {
       if (ConditionHash.length == 0)
           return false;

       return (ConditionHash[conditions[cond_hash].id] == cond_hash);
   }

  function getConditionHash() public view returns (uint256[] memory) {
    return ConditionHash;
  }

  function commitCondition(uint v, uint256 x, address datasource)
    public view returns (uint256 C, uint256 cond_hash)
  {
    require(Pubkeys[datasource][0] != uint256(0));
    uint256[2] memory c;
    c = ecMul(Pubkeys[datasource], v);
    c = ecAdd(c, ecMul(G1, x));
    C = CompressPoint(c);
    cond_hash = uint256(keccak256(abi.encodePacked(c[0], c[1])));
  }

  function registerCondition(uint256 C, uint256 cond_hash, address datasource) public {
    require(!conditionExist(cond_hash));
    conditions[cond_hash].C = C;
    conditions[cond_hash].datasource = datasource;
    conditions[cond_hash].owner = msg.sender;
    ConditionHash.push(cond_hash);
    conditionCount++;
    emit ConditionRegistered(cond_hash);
  }

  function computeCommitment(uint256 v, uint256[2] memory D, uint256 x )
   public view returns (uint256 C) {
    C = CompressPoint(ecAdd(ecMul(D, v), ecMul(G1, x)));
  }

  function generateCommitments(uint256 ds, uint dsVal, uint256 xD, uint watcherValLow, uint256 ylow, uint watcherValHigh, uint256 yhigh)
   public view returns (uint256[3] memory commitments) {
     uint256[2] memory dspub;
     dspub = ExpandPoint(ds);
     commitments[0] = CompressPoint(ecAdd(ecMul(dspub, dsVal), ecMul(G1, xD)));
     commitments[1] = CompressPoint(ecAdd(ecMul(dspub, watcherValLow), ecMul(G1, ylow)));
     commitments[2] = CompressPoint(ecAdd(ecMul(dspub, watcherValHigh), ecMul(G1, yhigh)));
  }
/*
  function computeSharedCommitment(uint256 conditionHash, uint256[3] memory commitments)
   public view returns (uint256[2] memory X)
  {
    // X_l = C_D - (C_l + \overline{C_l}) & = x_DG - (x_l + y_l)G
    uint256[2] memory temp1;
    uint256[2] memory temp2;
    uint256[2] memory temp3;
    uint256[2] memory temp4;
    temp1 = ExpandPoint(commitments[0]); // CD
    temp2 = ExpandPoint(commitments[1]); //oclow
    temp3 = ExpandPoint(conditions[conditionHash].Clow);
    temp4 = ecAdd(temp3, temp2);
    X[0] = CompressPoint(ecAdd(temp1, ecMul(temp4, N-1)));
    // X_u = (\overline{C_{u}} + C_D) - C_u & = (y_u-x_u)G + x_DG
    temp1 = ExpandPoint(commitments[0]); // CD
    temp2 = ExpandPoint(commitments[2]); //ochigh
    temp3 = ExpandPoint(conditions[conditionHash].Chigh);
    temp4 = ecAdd(temp1, temp2);
    X[1] = CompressPoint(ecAdd(temp4, ecMul(temp3, N-1)));
  }
*/
  function computeL(uint256 D, uint256 X1, uint256 X2) public pure returns (uint256 L)
  {
    L = uint256(keccak256(abi.encodePacked(D, X1, X2))) % N; // L = H(X1, X2)
  }
  function computeX(uint256 L, uint256 D, uint256 XD, uint256 XW) public view returns (uint256 X)
  {
    uint256[2] memory L1;
    uint256[2] memory L2;
    uint256[2] memory L3;
    uint256 h;
    h = uint256(keccak256(abi.encodePacked(L, D))) % N; // H(L,X1)
    L1 = ExpandPoint(D);
    L1 = ecMul(L1, h);
    h = uint256(keccak256(abi.encodePacked(L, XD))) % N; // H(L,X2)
    L2 = ExpandPoint(XD);
    L2 = ecMul(L2, h);
    L1 = ecAdd(L1,L2);
    h = uint256(keccak256(abi.encodePacked(L, XW))) % N; // H(L,X2)
    L3 = ExpandPoint(XW);
    L3 = ecMul(L3, h);
    X = CompressPoint(ecAdd(L1, L3));
  }

  function getRandomKey(uint256 r) public pure returns (uint256)
  {
    r = addmod(uint256(0),r,N);
    return r;
  }
  function getRandomPubKey(uint256 r) public view returns (uint256[2] memory X, uint256 x)
  {
    x = addmod(uint256(0),r,N);
    X = ecMul(G1, r);
  }

  function prepare_Datasource(uint256 RW, uint256 rD, uint256 xD)
   public view returns (uint256[2] memory RD, uint256[2] memory XD, uint256[2] memory R,uint256[2] memory newRW)
  {
    RD = ecMul(G1, rD);
    XD = ecMul(G1, xD);
    newRW = ExpandPoint(RW);
    R = ecAdd(RD, newRW);
  }

  function schnorrSign_Datasource(uint256 m, uint256[4] memory scalars,  uint256[2] memory R, uint256[2] memory D, uint256[2] memory XD, uint256[2] memory XW)
   public view returns (uint256[2] memory CD, uint256 sD)
  { // xD = H(L,X1)
    uint256 hW;
    hW = computeL(CompressPoint(D), CompressPoint(XD), CompressPoint(XW)); // here hW means L
    uint256 hD;
    uint256 hxD;
    // scalars = [v,d,xD,rD]
    hD = uint256(keccak256(abi.encodePacked(hW, CompressPoint(D)))) % N; // H(L,D)d
    hD = mulmod(hD,scalars[1],N);
    hxD = uint256(keccak256(abi.encodePacked(hW, CompressPoint(XD)))) % N; // H(L,XD)xD
    hxD = mulmod(hxD,scalars[2],N);
    hW = uint256(keccak256(abi.encodePacked(hW, CompressPoint(XW)))) % N; // H(L, XW)
    //uint256[2] memory X;
    // since we're done with XD, use XD as X
    XD = ecAdd(ecMul(G1, hD), ecMul(G1,hxD)); // H(L,D)D + H(L,XD)XD
    CD = ecMul(D, scalars[0]);
    CD = ecAdd(CD, XD); // CD = vD + H(L,D)D + H(L,XD)XD
    XD = ecAdd(ecMul(XW,hW),XD);
    hD = addmod(hD,hxD,N);
    // we're also done with hW, so use as a temp
    hW = CompressPoint(XD);
    sD = uint256(keccak256(abi.encodePacked(hW, CompressPoint(R), m))) % N;
    sD = mulmod(sD,hD,N);
    sD = addmod(sD,scalars[3],N);

  }

  function prepare_Watcher(uint256 v, uint256 xW, uint256[2] memory D, uint256[2] memory XD, uint256[2] memory XW, uint256[2] memory XL)
   public view returns(uint256[2] memory CcL, uint256 X, uint256 hW)
  {
    uint256 L;
    uint256 hD;
    uint256 hxD;
    // scalars = [v,xW,rW]
    L = computeL(CompressPoint(D), CompressPoint(XD), CompressPoint(XW));
    hD = uint256(keccak256(abi.encodePacked(L, D))) % N; // H(L,D)
    hxD = uint256(keccak256(abi.encodePacked(L, XD))) % N; // H(L,XD)
    hW = uint256(keccak256(abi.encodePacked(L, XW))) % N; // H(L,XW)
    hW = mulmod(hW,xW,N); // H(L,XW)xW
    // since we're done with XW, use XW as X
    XW = ecMul(G1,hW);
    XL = ecAdd(XW,XL);
    XL = ecMul(XL, uint256(-1) % N);
    CcL = ecMul(D, v);
    CcL = ecAdd(CcL,XL);
    // we're also done with XL
    XL = ecAdd(ecMul(G1, hD), ecMul(G1,hxD)); // H(L,D)D + H(L,XD)XD
    XW = ecAdd(XL,XW);
    X = CompressPoint(XW);

  }

  function schnorrSign_Watcher(uint256 m, uint256 X, uint256[2] memory R, uint256 rW, uint256 hW)
   public view returns (uint256 sW)
  {
    sW = uint256(keccak256(abi.encodePacked(X, CompressPoint(R), m))) % N; // H(X,R,m)
    sW = mulmod(hW,sW,N);
    sW = addmod(sW,rW,N);
  }

  function schnorrCoSign(uint256 sD, uint256 sW) public view returns (uint256 s)
  {
    s = addmod(sD,sW,N);
  }

  function schnorrVerify(uint256 X, uint256 m, uint256[2] memory signature)
   public view returns(bool success) {
   uint256[2] memory Xp;
   Xp = ExpandPoint(X);
   uint256 h;
   h = uint256(keccak256(abi.encodePacked(X, signature[0], m))) % N;
   uint256[2] memory sG;
   sG = ecMul(G1, signature[1]);
   Xp = ecMul(Xp, h);
   Xp = ecAdd(Xp, ExpandPoint(signature[0]));
   success = (sG[0]==Xp[0]) && (sG[1]==Xp[1]);
  }

  function schnorrVerify_Device(uint256 m, uint256[2] memory sig, uint256 D, uint256 XD, uint256 XW)
   public view returns (bool success)
  {
    uint256 X;
    uint256 L;
    L = computeL(D,XD,XW);
    X = computeX(L,D,XD,XW);
    if (schnorrVerify(X,m,sig)==true) {
      return true;
    }
    return false;
  }

  function schnorrSign_Device(uint256 m, uint256 X, uint256 x, uint256 r)
   public view returns(uint256[2] memory signature)
  {  // signature = [R, s] = [rG, r+H(X,R,m)x]
     uint256[2] memory R;
     R = ecMul(G1, r);
     signature[0] = CompressPoint(R);
     uint256 h;
     h = uint256(keccak256(abi.encodePacked(X, signature[0], m))) % N;
     signature[1] = mulmod(h, x, N);
     signature[1] = addmod(r, signature[1], N);
  }

  function schnorr_coSign(uint256[2] memory sig1, uint256[2] memory sig2)
   public view returns(uint256[2] memory sig)
  {
     uint256[2] memory temp1;
     uint256[2] memory temp2;
     temp1 = ExpandPoint(sig1[0]);
     temp2 = ExpandPoint(sig2[0]);
     sig[0] = CompressPoint(ecAdd(temp1, temp2));
     sig[1] = addmod(sig1[1], sig2[1], N);
  }

  function schnorrSign(uint256 m, uint256 X, uint256 x1, uint256 x2, uint256 r1, uint256 r2)
   public view returns(uint256[2] memory signature) {
     uint256[2] memory R1;
     uint256[2] memory R2;
     R1 = ecMul(G1, r1);
     R2 = ecMul(G1, r2);
     // R = R1 + R2
     signature[0] = CompressPoint(ecAdd(R1, R2));
     // H(X, R, m)
     uint256 h;
     h = uint256(keccak256(abi.encodePacked(X, signature[0], m))) % N;
     uint256 s1; // s1 = r1 + H*x1
     s1 = mulmod(h, x1, N);
     s1 = addmod(r1, s1, N);
     uint256 s2;
     s2 = mulmod(h, x2, N);
     s2 = addmod(r2, s2, N);
     signature[1] = addmod(s1, s2, N);
  }

  function proveCondition(uint256 m, uint256[2] memory X, uint256 xD, uint256[2] memory x, uint256[2] memory y, uint256[2] memory r1, uint256[2] memory r2)
   public view returns (uint256[2] memory signatureLow, uint256[2] memory signatureHigh) {
   // XL = x_D * G - (x_l + y_l) * G
   uint256 x2;
   x2 = addmod(x[0], y[0], N);
   x2 = N - x2;
   signatureLow = schnorrSign(m, X[0], xD, x2, r1[0], r2[0]);
   x2 = (y[1]-x[1]) % N ;
   signatureHigh = schnorrSign(m, X[1], xD, x2, r1[1], r2[1]);
  }

  /****************************************************************************/
  //Base EC Functions
  function ecAdd(uint256[2] memory p0, uint256[2] memory p1)
      public view returns (uint256[2] memory p2)
  {
      assembly {
          //Get Free Memory Pointer
          let p := mload(0x40)

          //Store Data for ECAdd Call
          mstore(p, mload(p0))
          mstore(add(p, 0x20), mload(add(p0, 0x20)))
          mstore(add(p, 0x40), mload(p1))
          mstore(add(p, 0x60), mload(add(p1, 0x20)))

          //Call ECAdd
          let success := staticcall(sub(gas, 2000), 0x06, p, 0x80, p, 0x40)

          // Use "invalid" to make gas estimation work
    switch success case 0 { revert(p, 0x80) }

    //Store Return Data
    mstore(p2, mload(p))
    mstore(add(p2, 0x20), mload(add(p,0x20)))
      }
  }

  function ecMul(uint256[2] memory p0, uint256 s)
      public view returns (uint256[2] memory p1)
  {
      assembly {
          //Get Free Memory Pointer
          let p := mload(0x40)

          //Store Data for ECMul Call
          mstore(p, mload(p0))
          mstore(add(p, 0x20), mload(add(p0, 0x20)))
          mstore(add(p, 0x40), s)

          //Call ECAdd
          let success := staticcall(sub(gas, 2000), 0x07, p, 0x60, p, 0x40)

          // Use "invalid" to make gas estimation work
    switch success case 0 { revert(p, 0x80) }

    //Store Return Data
    mstore(p1, mload(p))
    mstore(add(p1, 0x20), mload(add(p,0x20)))
      }
  }

  function CompressPoint(uint256[2] memory Pin)
      public pure returns (uint256 Pout)
  {
      //Store x value
      Pout = Pin[0];

      //Determine Sign
      if ((Pin[1] & 0x1) == 0x1) {
          Pout |= ECSignMask;
      }
  }

  function EvaluateCurve(uint256 x)
      public view returns (uint256 y, bool onCurve)
  {
      uint256 y_squared = mulmod(x,x, P);
      y_squared = mulmod(y_squared, x, P);
      y_squared = addmod(y_squared, 3, P);

      uint256 p_local = P;
      uint256 a_local = a;

      assembly {
          //Get Free Memory Pointer
          let p := mload(0x40)

          //Store Data for Big Int Mod Exp Call
          mstore(p, 0x20)                 //Length of Base
          mstore(add(p, 0x20), 0x20)      //Length of Exponent
          mstore(add(p, 0x40), 0x20)      //Length of Modulus
          mstore(add(p, 0x60), y_squared) //Base
          mstore(add(p, 0x80), a_local)   //Exponent
          mstore(add(p, 0xA0), p_local)   //Modulus

          //Call Big Int Mod Exp
          let success := staticcall(sub(gas, 2000), 0x05, p, 0xC0, p, 0x20)
          //let success := call(sub(gas, 2000), 0x05, 0, p, 0xC0, p, 0x20)
          // Use "invalid" to make gas estimation work
    //switch success case 0 { revert(p, 0xC0) }
    switch success case 0 { invalid()}

    //Store Return Data
    y := mload(p)
      }

      //Check Answer
      onCurve = (y_squared == mulmod(y, y, P));
  }

  function ExpandPoint(uint256 Pin)
      public view returns (uint256[2] memory Pout)
  {
      //Get x value (mask out sign bit)
      Pout[0] = Pin & (~ECSignMask);

      //Get y value
      bool onCurve;
      uint256 y;
      (y, onCurve) = EvaluateCurve(Pout[0]);

      //TODO: Find better failure case for point not on curve
      if (!onCurve) {
          Pout[0] = 0;
          Pout[1] = 0;
      }
      else {
          //Use Positive Y
          if ((Pin & ECSignMask) != 0) {
              if ((y & 0x1) == 0x1) {
                  Pout[1] = y;
              } else {
                  Pout[1] = P - y;
              }
          }
          //Use Negative Y
          else {
              if ((y & 0x1) == 0x1) {
                  Pout[1] = P - y;
              } else {
                  Pout[1] = y;
              }
          }
      }
  }

  //=====Ring Signature Functions=====
  //Return H = alt_bn128 evaluated at keccak256(p)
  function HashPoint(uint256[2] memory p)
      internal view returns (uint256[2] memory h)
  {
      bool onCurve;
      h[0] = uint256(keccak256(abi.encodePacked(p[0], p[1]))) % N;

      while(!onCurve) {
          (h[1], onCurve) = EvaluateCurve(h[0]);
          h[0]++;
      }
      h[0]--;
  }

  function KeyImage(uint256 xk, uint256[2] memory Pk)
      internal view returns (uint256[2] memory Ix)
  {
      //Ix = xk * HashPoint(Pk)
      Ix = HashPoint(Pk);
      Ix = ecMul(Ix, xk);
  }

  //SubMul = (alpha - c*xk) % N
  function SubMul(uint256 alpha, uint256 c, uint256 xk)
      internal pure returns (uint256 s)
  {
      s = mulmod(c, xk, N);
      s = N - s;
      s = addmod(alpha, s, N);
  }


}
