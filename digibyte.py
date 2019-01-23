from ecdsa import SigningKey,VerifyingKey, SECP256k1
import ecdsa
from binascii import hexlify, unhexlify
import hashlib
from hashlib import sha256
import base58
from os import urandom
import copy



def sha256ripemd160(data):
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(hashlib.sha256(data).digest())
    return ripemd160.digest()

def dsha256(data):
    return sha256(sha256(data).digest()).digest()

def pubKeytoAddress(publicKeyHex):
    h = sha256ripemd160(unhexlify(publicKeyHex))
    checksum = dsha256(b'\x1e' + h)[:4]
    return base58.b58encode(b'\x1e' + h + checksum)

def compress(vk_hex):
    assert len(vk_hex) == 128
    x = vk_hex[:64]
    y = vk_hex[64:]
    if int(y[-1])&1 : prefix = b'03'
    else : prefix = b'02'
    return prefix + x


def decompress(compressed_vk_hex):
    prefix = compressed_vk_hex[:2]
    
    x = int(compressed_vk_hex[2:],16)

    p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    y_squared = (x**3 + 7) % p
    y = pow(y_squared,(p+1)>>2,p)
    
    if prefix == b'03' and y&1 == 0:
        y = p-y
    elif prefix == b'02' and y&1 == 1:
        y = p-y
        
    return '{:032x}{:032x}'.format(x,y)
    
    

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
    return hexlify(sk.sign_digest(digest,sigencode=ecdsa.util.sigencode_der))+ b'01'

def verify_digest(digest,sig,vk):
    return vk.verify_digest(unhexlify(sig)[:-1],digest,sigdecode=ecdsa.util.sigdecode_der)

#TODO : direcly parse bytes
def parseVariableLengthInteger(data):
    size = int(data[:2],16)
    if size<0xFD:
        return data[:2]
    elif size == 0xFD:
        return data[2:6]
    elif size == 0xFE:
        return data[2:10]
    elif size == 0xFF:
        return data[2:18]
    else:
        raise ValueError('Invalid variable length integer input')
    
#TODO : direcly parse bytes
def encodeVariableLengthInteger(integer):
    if 0 <= integer < 0xFD:
        return bytes('{:02x}'.format(integer),'utf-8')
    elif 0xFC < integer < 0x10000:
        return bytes('FD{:04x}'.format(integer),'utf-8')
    elif 0xFFFF < integer < 0x100000000:
        return bytes('FE{:08x}'.format(integer),'utf-8')
    elif 0xFFFFFFFF < integer < 0x10000000000000000:
        return bytes('FF{:016x}'.format(integer),'utf-8')
    else:
        raise ValueError('Invalid integer')
    
#TODO : direcly parse bytes
def parseSignedRawTransaction(transaction):
    TX = {}
    pointer = 0
    TX['format'] = transaction[pointer:pointer+8]
    pointer += 8
    TX['Inputs'] = parseVariableLengthInteger(transaction[pointer:pointer+18])
    pointer += len(TX['Inputs'])
    
    TX['vin'] = []
    
    for i in range(int(TX['Inputs'],16)):
        tmp = {}
        
        tmp['txid'] = transaction[pointer:pointer+64]
        pointer += 64
        tmp['Index'] = transaction[pointer:pointer+8]
        pointer += 8
        tmp['Length'] = parseVariableLengthInteger(transaction[pointer:pointer+18])
        
        pointer += len(tmp['Length'])
        
        scriptLength = int(tmp['Length'],16)<<1
        tmp['ScriptSig'] = transaction[pointer:pointer+scriptLength]
        pointer += scriptLength
        tmp['Sequence'] = transaction[pointer:pointer+8]
        pointer += 8

        TX['vin'] += [tmp]
        
    TX['Outputs'] = transaction[pointer:pointer+2]
    pointer += 2

    TX['vout'] = []
    
    for i in range(int(TX['Outputs'],16)):
        tmp = {}
        tmp ['Value'] = transaction[pointer:pointer+16]
        pointer += 16
        tmp ['Length'] = parseVariableLengthInteger(transaction[pointer:pointer+18])
        pointer += len(tmp ['Length'])
        scriptLength = int(tmp['Length'],16)<<1
        tmp ['ScriptPubKey'] = transaction[pointer:pointer+scriptLength]
        pointer += scriptLength
        TX['vout'] += [tmp]
        
    TX['Locktime'] = transaction[pointer:pointer+8]

    return TX

#TODO : direcly parse bytes
def verifySignedRawTransaction(transaction,inputs):
    TX = parseSignedRawTransaction(transaction)

    for i in range(len(TX['vin'])):
 
        cleanTX = copy.deepcopy(TX)
        
        scriptSig = cleanTX['vin'][i]['ScriptSig']

        scriptSigLen = parseVariableLengthInteger(scriptSig)
        
        signature = scriptSig[len(scriptSigLen):(int(scriptSigLen,16)<<1)+len(scriptSigLen)]

        vk = VerifyingKey.from_string(unhexlify(decompress(scriptSig[len(scriptSigLen)+(int(scriptSigLen,16)<<1)+2:])), curve=SECP256k1)

        if sha256ripemd160(unhexlify(compress(hexlify(vk.to_string())))) != unhexlify(bytes(inputs[i]['scriptPubKey'],'utf-8'))[3:-2]:
            return False

        for j in range(len(TX['vin'])):
            cleanTX['vin'][j]['Length'] = b'00'
            cleanTX['vin'][j]['ScriptSig'] = b''
        
        tmp = cleanTX.copy()
        
        tmp['vin'][i]['Length'] = encodeVariableLengthInteger(len(inputs[i]['scriptPubKey'])>>1)
        tmp['vin'][i]['ScriptSig'] = bytes(inputs[i]['scriptPubKey'],'utf-8')

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
        rawtmp += signature[-2:] + b'000000'

        signed = dsha256(unhexlify(rawtmp))
  
        v = verify_digest(signed,signature,vk)
        if v != True:
            return False
    return True
        

inputs = [{"scriptPubKey":"76a914128bef368aee81f7f89a0206e77aabbfd5b4f05b88ac"},
          {"scriptPubKey":"76a914128bef368aee81f7f89a0206e77aabbfd5b4f05b88ac"}]

x = b'010000000272f5fe89b3db1343301384ed5981b4b3e1cfabe9abcb48b92cdfae1c34b55ac7020000006a473044022041be4bf959fb9296872b71b17580b4ec0be79ccc2f7232360b1af23148b0797f02205bca0687905e219fe4b068c7a8fd6f231827a44fee10145af6df7fa5d1f7e319012103a81a7d62c25af7945e225b74f75478e53672b585d9ac8ec88344f4b92f34e843ffffffff72f5fe89b3db1343301384ed5981b4b3e1cfabe9abcb48b92cdfae1c34b55ac7000000006a47304402201bfe24973497bf7b15dba2ecbae03ed496c60f03e8998f1aaf8971367f63637b022042e5ccb818dbc931e77a8dc935bef004f30263e11176a791a35f0db0f1b80536012103a81a7d62c25af7945e225b74f75478e53672b585d9ac8ec88344f4b92f34e843ffffffff03c0270900000000001976a914128bef368aee81f7f89a0206e77aabbfd5b4f05b88ac0000000000000000216a1f54686973206973206120746573742031353a31312032352e31312e3230313820961877000000001976a914128bef368aee81f7f89a0206e77aabbfd5b4f05b88ac00000000'
v = verifySignedRawTransaction(x,inputs)
print(v)
