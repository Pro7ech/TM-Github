from ecdsa import SigningKey,VerifyingKey, SECP256k1
import ecdsa
from binascii import hexlify, unhexlify
import hashlib
from hashlib import sha256
import base58
from os import urandom
import copy
import ssl



def sha256ripemd160(data):
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(hashlib.sha256(data).digest())
    return ripemd160.digest()

def dsha256(data):
    return sha256(sha256(data).digest()).digest()

def pubKeytoAddress(publicKey):
    h = sha256ripemd160(publicKeyHex)
    checksum = dsha256(b'\x1e' + h)[:4]
    return base58.b58encode(b'\x1e' + h + checksum)

def compress(vk):
    vk = vk.to_string()
    assert len(vk) == 64
    x = vk[:32]
    y = vk[32:]
    if y[-1]&1 : prefix = b'\x03'
    else : prefix = b'\x02'
    return prefix + x


def decompress(compressed_vk):

    prefix = compressed_vk[:1]

    x = int.from_bytes(compressed_vk[1:], byteorder='big')
    
    p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    y_squared = (pow(x,3,p) + 7) % p
    y = pow(y_squared,(p+1)>>2,p)
    
    if prefix == b'\x03' and y&1 == 0:
        y = p-y
    elif prefix == b'\x02' and y&1 == 1:
        y = p-y
 
    return compressed_vk[1:] + (y).to_bytes(32,byteorder='big')
    
    

def generateAddress(prefix=b''):
    prefix = prefix.lower()
    while True:
        sk = SigningKey.from_string(urandom(32), curve=SECP256k1)
        vk = sk.get_verifying_key()
        x = vk.to_string()[:32]
        if x[-1]&1 : x = b'\x03' + x
        else : x = b'\x02' + x
        h = sha256ripemd160(x)
        address = base58.b58encode(b'\x1e' + h + b'\x00\x00\x00\x00')
        if address[:len(prefix)].lower() == prefix:
            break
    print(hexlify(sk.to_string()))
    checksum = dsha256(b'\x1e' + h)[:4]
    address = base58.b58encode(b'\x1e' + h + checksum)
    print(address)

    
def sign_digest(digest,sk):
    return sk.sign_digest(digest,sigencode=ecdsa.util.sigencode_der)

def verify_digest(digest,sig,vk):
    return vk.verify_digest(sig[:-1],digest,sigdecode=ecdsa.util.sigdecode_der)


def parseVariableInteger(data):

    size = int.from_bytes(data[:1], byteorder='little')
    
    if size<0xFD:
        return data[:1]
    elif size == 0xFD:
        return data[:3]
    elif size == 0xFE:
        return data[:5]
    elif size == 0xFF:
        return data[:9]
    else:
        raise ValueError('Invalid variable length integer input')


def getVariableIntegerValue(data):
    size = int.from_bytes(data[:1], byteorder='little')
    
    if size<0xFD:
        return size
    elif size == 0xFD:
        return int.from_bytes(data[1:3], byteorder='little') 
    elif size == 0xFE:
        return int.from_bytes(data[1:5], byteorder='little')
    elif size == 0xFF:
        return int.from_bytes(data[1:9], byteorder='little')
    else:
        raise ValueError('Invalid variable length integer input')
    
    

def encodeVariableInteger(integer):
    
    if 0 <= integer < 0xFD:
        return (integer).to_bytes(1,byteorder='little')
    elif 0xFC < integer < 0x10000:
        return b'\xfd' + (integer).to_bytes(2,byteorder='little')
    elif 0xFFFF < integer < 0x100000000:
        return b'\xFE' + (integer).to_bytes(4,byteorder='little')
    elif 0xFFFFFFFF < integer < 0x10000000000000000:
        return b'\xff' + (integer).to_bytes(8,byteorder='little')
    else:
        raise ValueError('Invalid integer')



def parseSignedRawTransaction(transaction):
    transaction = unhexlify(transaction)
    
    TX = {}
    pointer = 0
    TX['format'] = transaction[pointer:pointer+4]
    pointer += 4
    
    TX['Inputs'] = parseVariableInteger(transaction[pointer:pointer+9])
    pointer += len(TX['Inputs'])
    
    TX['vin'] = []
    
    for i in range(getVariableIntegerValue(TX['Inputs'])):
        tmp = {}
        
        tmp['txid'] = transaction[pointer:pointer+32]
        pointer += 32
        
        tmp['Index'] = transaction[pointer:pointer+4]
        pointer += 4
        
        tmp['Length'] = parseVariableInteger(transaction[pointer:pointer+9])
        pointer += len(tmp['Length'])
        
        scriptLength = getVariableIntegerValue(tmp['Length'])
        
        tmp['ScriptSig'] = transaction[pointer:pointer+scriptLength]
        pointer += scriptLength
        
        tmp['Sequence'] = transaction[pointer:pointer+4]
        pointer += 4

        TX['vin'] += [tmp]
        
    TX['Outputs'] = parseVariableInteger(transaction[pointer:pointer+9])
    pointer += len(TX['Outputs'])

    TX['vout'] = []

    for i in range(getVariableIntegerValue(TX['Outputs'])):
        tmp = {}
        tmp ['Value'] = transaction[pointer:pointer+8]
        pointer += 8
        
        tmp ['Length'] = parseVariableInteger(transaction[pointer:pointer+9])
        pointer += len(tmp ['Length'])
        
        scriptLength = getVariableIntegerValue(tmp['Length'])
        
        tmp['ScriptPubKey'] = transaction[pointer:pointer+scriptLength]
        pointer += scriptLength
        
        TX['vout'] += [tmp]
        
    TX['Locktime'] = transaction[pointer:pointer+4]

    return TX



def verifySignedRawTransaction(transaction,inputs):
    TX = parseSignedRawTransaction(transaction)

    for i in range(len(TX['vin'])):
 
        cleanTX = copy.deepcopy(TX)
        
        scriptSig = cleanTX['vin'][i]['ScriptSig']

        PUSHDATA = int.from_bytes(scriptSig[:1],byteorder='big')
        scriptSig = scriptSig[1:]
        
        signature = scriptSig[:PUSHDATA]
        scriptSig = scriptSig[PUSHDATA:]

        PUSHDATA = int.from_bytes(scriptSig[:1],byteorder='big')
        scriptSig = scriptSig[1:]
        
        compressed_vk = scriptSig[:PUSHDATA]
        scriptSig = scriptSig[PUSHDATA:]

        vk = VerifyingKey.from_string(decompress(compressed_vk), curve=SECP256k1)

        pubKeyHash = inputs[i]['scriptPubKey'][3:-2]

        if sha256ripemd160(compressed_vk) != pubKeyHash:
            return False
        
        for j in range(len(TX['vin'])):
            cleanTX['vin'][j]['Length'] = b'\x00'
            cleanTX['vin'][j]['ScriptSig'] = b''
        
        tmp = cleanTX.copy()
        
        tmp['vin'][i]['Length'] = encodeVariableInteger(len(inputs[i]['scriptPubKey']))
        tmp['vin'][i]['ScriptSig'] = inputs[i]['scriptPubKey']

        rawtmp = b''
        rawtmp += tmp['format']
        rawtmp += tmp['Inputs']
        
        for j in range(len(tmp['vin'])):
            rawtmp += tmp['vin'][j]['txid']
            rawtmp += tmp['vin'][j]['Index']
            rawtmp += tmp['vin'][j]['Length']
            rawtmp += tmp['vin'][j]['ScriptSig']
            rawtmp += tmp['vin'][j]['Sequence']
            
        rawtmp += tmp['Outputs']
        
        for j in range(len(tmp['vout'])):
            rawtmp += tmp['vout'][j]['Value']
            rawtmp += tmp['vout'][j]['Length']
            rawtmp += tmp['vout'][j]['ScriptPubKey']

        rawtmp += tmp['Locktime']
        rawtmp += signature[-1:] + b'\x00\x00\x00'

        signed = dsha256(rawtmp)
  
        v = verify_digest(signed,signature,vk)
        if v != True:
            return False
    return True


class transaction(object):
    def __init__(self):
        self.tx = {}
        self.tx['version'] = (1).to_bytes(4,byteorder='little')
        self.tx['nVin'] = 0
        self.tx['vin'] = []
        self.tx['nVout'] = 0
        self.tx['vout'] = []
        self.tx['locktime'] = b'\x00\x00\x00\x00'

        self.change = b''
        self.totalValueIn = 0

    def addInputs(self,vin):
        self.tx['nVin'] += 1

        if 'statoshis' not in vin:
            self.totalValueIn += int(round(vin['amount']*100000000))
        else:
            self.totalValueIn += vin['satoshis']

        tmp = {}
        tmp['previousTXID'] = unhexlify(vin['txid'])[::-1]
        tmp['previousVoutIndex'] = (vin['vout']).to_bytes(4,byteorder='little')
        tmp['scriptLength'] = len(unhexlify(vin['scriptPubKey'])).to_bytes(1,byteorder='little')
        tmp['scriptSig'] = unhexlify(vin['scriptPubKey'])
        tmp['sequence'] = b'\xff\xff\xff\xff'
        
        self.tx['vin'] += [tmp]
       
    def addDestination(self,address,amount):
        pubKeyHash = addresstopubKeyHash(address)
        self.tx['nVout'] += 1
        self.totalValueIn -= amount

        tmp = {}
        tmp['amount'] = (amount).to_bytes(8,byteorder='little')
        tmp['scriptLength'] = b''
        tmp['scriptPubKey'] = b'\x76\xa9' + len(pubKeyHash).to_bytes(1,byteorder='big') + pubKeyHash + b'\x88\xac'
        tmp['scriptLength'] = encodeVariableInteger(len(tmp['scriptPubKey']))

        self.tx['vout'] += [tmp]

    def changeAddress(self,address):
        self.change = address
        
    def addData(self,data, amount=0):
        self.tx['nVout'] += 1
        self.totalValueIn -= amount

        tmp = {}
        tmp['amount'] = (amount).to_bytes(8,byteorder='little')
        tmp['scriptLength'] = b''
        tmp['scriptPubKey'] = b'\x6a' + len(data).to_bytes(1,byteorder='big') + data
        tmp['scriptLength'] = encodeVariableInteger(len(tmp['scriptPubKey']))

        self.tx['vout'] += [tmp]

    def sign(self, sk):
        
        vk = sk.get_verifying_key()
        vk_compressed = compress(vk)
        
        signatures = []

        size = self.tx['nVin']*180 + self.tx['nVout']*34 + 10 + self.tx['nVin'] + 80

        fee = 100 * size

        if fee < 100000:
            fee = 100000

        self.addDestination(self.change,self.totalValueIn-fee)
        
        for i in range(self.tx['nVin']):

            serializedTX = b''
            serializedTX += self.tx['version']
            
            serializedTX += encodeVariableInteger(self.tx['nVin'])
            
            for j in range(self.tx['nVin']):
                
                if j == i:
                    
                    serializedTX += self.tx['vin'][j]['previousTXID']
                    serializedTX += self.tx['vin'][j]['previousVoutIndex']
                    serializedTX += self.tx['vin'][j]['scriptLength']
                    serializedTX += self.tx['vin'][j]['scriptSig']
                    serializedTX += self.tx['vin'][j]['sequence']
                    
                else :
                    
                    serializedTX += self.tx['vin'][j]['previousTXID']
                    serializedTX += self.tx['vin'][j]['previousVoutIndex']
                    serializedTX += b'\x00'
                    serializedTX += b''
                    serializedTX += self.tx['vin'][j]['sequence']
                
            serializedTX += encodeVariableInteger(self.tx['nVout'])
            
            for j in range(self.tx['nVout']):
                
                serializedTX += self.tx['vout'][j]['amount']
                serializedTX += self.tx['vout'][j]['scriptLength']
                serializedTX += self.tx['vout'][j]['scriptPubKey']
                
            serializedTX += self.tx['locktime']
            serializedTX += b'\x01\x00\x00\x00'

            signature = sk.sign_digest(dsha256(serializedTX),sigencode=ecdsa.util.sigencode_der)
            
            rlength=signature[3+signature[3]+2]
            
            r = int.from_bytes(signature[3+signature[3]+3:],byteorder='big')
            
            n = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
            
            if r > (n>>1):
                r = n-r
                
            sig = signature[4:4+signature[3]]
            r = (r).to_bytes(32,byteorder='big')

            signature =  b'\x02' + len(sig).to_bytes(1,byteorder='big') +sig+ b'\x02' + len(r).to_bytes(1,byteorder='big') + r

            signature = b'\x30' + len(signature).to_bytes(1,byteorder='big') + signature + b'\x01'
            
            self.tx['vin'][i]['scriptSig'] = len(signature).to_bytes(1,byteorder='big') + signature  + len(vk_compressed).to_bytes(1,byteorder='big') + vk_compressed
            self.tx['vin'][i]['scriptLength'] = encodeVariableInteger(len(self.tx['vin'][i]['scriptSig']))
            

    def serialize(self):
        serializedTX = b''
        serializedTX += self.tx['version']
        
        serializedTX += encodeVariableInteger(self.tx['nVin'])
        
        for i in range(self.tx['nVin']):
            
            serializedTX += self.tx['vin'][i]['previousTXID']
            serializedTX += self.tx['vin'][i]['previousVoutIndex']
            serializedTX += self.tx['vin'][i]['scriptLength']
            serializedTX += self.tx['vin'][i]['scriptSig']
            serializedTX += self.tx['vin'][i]['sequence']
            
        serializedTX += encodeVariableInteger(self.tx['nVout'])
        
        for i in range(self.tx['nVout']):
            
            serializedTX += self.tx['vout'][i]['amount']
            serializedTX += self.tx['vout'][i]['scriptLength']
            serializedTX += self.tx['vout'][i]['scriptPubKey']
            
        serializedTX += self.tx['locktime']
        
        return hexlify(serializedTX)

inputs = [{"scriptPubKey":unhexlify("76a914128bef368aee81f7f89a0206e77aabbfd5b4f05b88ac")},
          {"scriptPubKey":unhexlify("76a914128bef368aee81f7f89a0206e77aabbfd5b4f05b88ac")}]

x = b'010000000272f5fe89b3db1343301384ed5981b4b3e1cfabe9abcb48b92cdfae1c34b55ac7020000006a473044022041be4bf959fb9296872b71b17580b4ec0be79ccc2f7232360b1af23148b0797f02205bca0687905e219fe4b068c7a8fd6f231827a44fee10145af6df7fa5d1f7e319012103a81a7d62c25af7945e225b74f75478e53672b585d9ac8ec88344f4b92f34e843ffffffff72f5fe89b3db1343301384ed5981b4b3e1cfabe9abcb48b92cdfae1c34b55ac7000000006a47304402201bfe24973497bf7b15dba2ecbae03ed496c60f03e8998f1aaf8971367f63637b022042e5ccb818dbc931e77a8dc935bef004f30263e11176a791a35f0db0f1b80536012103a81a7d62c25af7945e225b74f75478e53672b585d9ac8ec88344f4b92f34e843ffffffff03c0270900000000001976a914128bef368aee81f7f89a0206e77aabbfd5b4f05b88ac0000000000000000216a1f54686973206973206120746573742031353a31312032352e31312e3230313820961877000000001976a914128bef368aee81f7f89a0206e77aabbfd5b4f05b88ac00000000'
v = verifySignedRawTransaction(x,inputs)
print(v)
