from ecdsa import SigningKey,VerifyingKey, SECP256k1
import ecdsa
from binascii import hexlify, unhexlify
import hashlib
from hashlib import sha256
import base58
from os import urandom
import copy
import json
import requests
import datetime

class transaction(object):
    
    #explorerURL = "https://digibyteblockexplorer.com/api"
    explorerURL = "https://digiexplorer.info/api"
    
    def __init__(self):
        self.tx = {}
        self.tx['version'] = (1).to_bytes(4,byteorder='little')
        self.tx['nVin'] = 0
        self.tx['vin'] = []
        self.tx['nVout'] = 0
        self.tx['vout'] = []
        self.tx['locktime'] = b'\x00\x00\x00\x00'

        self.change = b''

        self.isSigned = False

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

        tmp = {}
        tmp['amount'] = (amount).to_bytes(8,byteorder='little')
        tmp['scriptLength'] = b''
        tmp['scriptPubKey'] = b'\x76\xa9' + len(pubKeyHash).to_bytes(1,byteorder='big') + pubKeyHash + b'\x88\xac'
        tmp['scriptLength'] = encodeVariableInteger(len(tmp['scriptPubKey']))

        self.tx['vout'] += [tmp]

    def changeAddress(self,address):
        self.change = address
        
    def addData(self,data, amount=0):
        if len(data)>80:
            raise Exception("OP_RETURN > 80 bytes")
            return
            
        self.tx['nVout'] += 1

        tmp = {}
        tmp['amount'] = (amount).to_bytes(8,byteorder='little')
        tmp['scriptLength'] = b''
        tmp['scriptPubKey'] = b'\x6a' + len(data).to_bytes(1,byteorder='big') + data
        tmp['scriptLength'] = encodeVariableInteger(len(tmp['scriptPubKey']))

        self.tx['vout'] += [tmp]

    def locktime(self,locktime):
        assert 0<= locktime <= 0xFFFFFFFF
        self.locktime = (locktime).to_bytes(4,byteorder='little')

    def totalValue(self):
        
        totalValue = 0
        
        for i in range(self.tx['nVin']):
            totalValue += self.tx['vin'][i]['amount']

        for i in range(self.tx['nVout']):
            totalValue -= self.tx['vout'][i]['amout']

        return totalValue
            

    def sign(self, sk):

        size = self.tx['nVin']*180 + self.tx['nVout']*34 + 10 + self.tx['nVin'] + 80

        fee = 100 * size

        if fee < 100000:
            fee = 100000

        if totalValue - fee <0:
            raise Exception('Not enough inputs to cover outputs and fee, missing {}'.format(totalValue-fee))

        vk = sk.get_verifying_key()
        vk_compressed = compress(vk)
        
        signatures = []

        self.addDestination(self.change,self.totalValue-fee)
        
        for i in range(self.tx['nVin']):

            serializedTX = b''
            serializedTX += self.tx['version']
            
            serializedTX += encodeVariableInteger(self.tx['nVin'])
            
            for j in range(self.tx['nVin']):
                serializedTX += self.tx['vin'][j]['previousTXID']
                serializedTX += self.tx['vin'][j]['previousVoutIndex']

                if j == i:
                    serializedTX += self.tx['vin'][j]['scriptLength']
                    serializedTX += self.tx['vin'][j]['scriptSig']
                else :
                    serializedTX += b'\x00'

                serializedTX += self.tx['vin'][j]['sequence']
                
            serializedTX += encodeVariableInteger(self.tx['nVout'])
            
            for j in range(self.tx['nVout']):
                
                serializedTX += self.tx['vout'][j]['amount']
                serializedTX += self.tx['vout'][j]['scriptLength']
                serializedTX += self.tx['vout'][j]['scriptPubKey']
                
            serializedTX += self.tx['locktime']
            serializedTX += b'\x01\x00\x00\x00'

            signature = sign_digest(dsha256(serializedTX),sk) + b'\x01'
            
            self.tx['vin'][i]['scriptSig'] = len(signature).to_bytes(1,byteorder='big') + signature  + len(vk_compressed).to_bytes(1,byteorder='big') + vk_compressed
            self.tx['vin'][i]['scriptLength'] = encodeVariableInteger(len(self.tx['vin'][i]['scriptSig']))

        self.isSigned = True

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


    def send(self):
        if self.isSigned != True:
            raise Exception("Trying to send an unsigned transaction")
            return

        url = self.explorerURL + '/tx/send/'
        headers = {'content-type' : 'application/json'}
        data = json.dumps({'rawtx':self.serialize().decode('utf-8')})
        
        r = requests.post(url=url,headers=headers,data=data)

        if r.status_code == 200:
            return r.json()
        else:
            return {'error': r.text}


def importPrivateKey(path):
    with open(path,'rb') as F:
        key = F.read()
        return SigningKey.from_string(unhexlify(key), curve=SECP256k1)


def sha256ripemd160(data):
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(hashlib.sha256(data).digest())
    return ripemd160.digest()


def dsha256(data):
    return sha256(sha256(data).digest()).digest()


def privateKeytoAddress(sk):
    vk = sk.get_verifying_key()
    vk_compressed = compress(vk)
    return pubKeytoAddress(vk_compressed)


def pubKeytoAddress(publicKey):
    h = sha256ripemd160(publicKey)
    checksum = dsha256(b'\x1e' + h)[:4]
    return base58.b58encode(b'\x1e' + h + checksum)


def addresstopubKeyHash(address):
    tmp = base58.b58decode(address)
    return tmp[1:-4]


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
    if prefix == b'\x03' and y&1 == 0: y = p-y
    elif prefix == b'\x02' and y&1 == 1: y = p-y
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


#Custom DER encoding makes the management of r and s easier
def sign_digest(digest,sk):
    
    signature = sk.sign_digest(digest)

    r = int.from_bytes(signature[:32],byteorder='big')
    s = int.from_bytes(signature[32:],byteorder='big')
            
    n = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
           
    if s > (n>>1): s = n-s

    r = (r).to_bytes(32,byteorder='big')
    s = (s).to_bytes(32,byteorder='big')

    if r[0] > 0x7f: r = b'\x00' + r
    if s[0] > 0x7f: s = b'\x00' + s

    tmp =  b'\x02' + len(r).to_bytes(1,byteorder='big') + r + b'\x02' + len(s).to_bytes(1,byteorder='big') + s

    signature = b'\x30' + len(tmp).to_bytes(1,byteorder='big') + tmp

    return signature


def verify_digest(digest,sig,vk):
    return vk.verify_digest(sig[:-1],digest,sigdecode=ecdsa.util.sigdecode_der)


def parseVariableInteger(data):

    size = int.from_bytes(data[:1], byteorder='little')
    
    if size<0xFD: return data[:1]
    elif size == 0xFD: return data[:3]
    elif size == 0xFE: return data[:5]
    elif size == 0xFF: return data[:9]
    else: raise ValueError('Invalid variable length integer input')


def getVariableIntegerValue(data):
    size = int.from_bytes(data[:1], byteorder='little')
    
    if size<0xFD: return size
    elif size == 0xFD: return int.from_bytes(data[1:3], byteorder='little') 
    elif size == 0xFE: return int.from_bytes(data[1:5], byteorder='little')
    elif size == 0xFF: return int.from_bytes(data[1:9], byteorder='little')
    else: raise ValueError('Invalid variable length integer input')
    

def encodeVariableInteger(integer):
    
    if 0 <= integer < 0xFD: return (integer).to_bytes(1,byteorder='little')
    elif 0xFC < integer < 0x10000: return b'\xfd' + (integer).to_bytes(2,byteorder='little')
    elif 0xFFFF < integer < 0x100000000: return b'\xfe' + (integer).to_bytes(4,byteorder='little')
    elif 0xFFFFFFFF < integer < 0x10000000000000000: return b'\xff' + (integer).to_bytes(8,byteorder='little')
    else: raise ValueError('Invalid integer')


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
        print(rawtmp)
        signed = dsha256(rawtmp)
  
        v = verify_digest(signed,signature,vk)
        if v != True:
            return False
    return True

        
        
def getUTXOs(address):

    if type(address) != bytes:
        address = bytes(address,'utf-8')
    
    r = requests.get(b'https://digiexplorer.info/api/addr/' + address + b'/utxo' )
    if r.status_code == 200:
        return r.json()
    else:
        return {'error' : r.text}





sk = importPrivateKey('privateKey.txt')
address = privateKeytoAddress(sk)
UTXO = getUTXOs(address)


tx = transaction()
tx.addInputs(UTXO[0])
tx.addData(bytes(str(datetime.datetime.now()),'utf-8'))
tx.changeAddress(address)
tx.sign(sk)
#r = tx.send()
#print(r)


