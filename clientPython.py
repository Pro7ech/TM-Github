import json
import requests
from pyblake2 import blake2b
from binascii import unhexlify,hexlify
import base64
import asyncio
import websockets
import ssl
import pathlib


#Hash the provided data with the provided key. Default output is 256 bits.
#If data consist in several objects, they need to be provided in a list.
def Blake2b(data, key =b'', outlen = 32):
    """
        INPUT  data   :  string or bytes
               key    :  bytes
               outlen :  integer [0,64]

        RESULT digest :  bytes
    """
    h = blake2b(key = key,digest_size = outlen)
    for i in data:
        if type(i) != bytes:
            i = bytes(i,'utf-8')
        h.update(i)
    return h.digest()

#Generates a TAG from a message, a key and a challenge. 
def computeTag(message, mackey, challenge):
    """
        INPUT  message   :  string or bytes
               mackey    :  hexstring
               challenge :  string or bytes

        RESULT tag       : bytes
    """
    return str(base64.b64encode(Blake2b([message,challenge],unhexlify(mackey))),'utf-8')

ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ssl_context.load_verify_locations(pathlib.Path(__file__).with_name('certificate.pem'))
ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ssl_context.load_verify_locations(pathlib.Path(__file__).with_name('certificate.pem'))

#WesocketServer
ws_address = 'wss://localhost:3000/request'

#External Explorer
explorerUrl = "https://digiexplorer.info/api" #"http://192.168.1.127:3001/insight-digibyte-api"
marketUrl = "https://api.coinmarketcap.com/v1/ticker/digibyte/"

#Local Explorer
#local_explorerUrl_API = "http://192.168.1.125:3001/insight-digibyte-api"
#local_explorerUrL_UI = "http://192.168.1.125:3001/insight"

mackey = "2f3bf6e7f45367cd7687d2fc6e611cbefad81e3ee76d33ad91af0bdc178ad732"
txid = "a3371fb6b08cfdba31f1e82cbdd0e602ec2da97e455720c283a6bc95b3d201e5"
data = "This is a test 15:11 25.11.2018"
wallet = "DEk2TrFCjqm8kCV1A1M6gZq9CeBB2XNViE" #"DRmCEXvsPVbNc7Fuo3fVKMukdoQ6TEN8UB"

#Sends a request to the websocket server to retrieve an OP_RETURN from a transaction
async def getOPReturn(txid,mackey):
    """
        INPUT  txid   :  hexstring
               mackey :  hexstring

        OUTPUT response : {status : true/false , OP_RETURN : string} (JSON)
        
        ex : {'status': True, 'OP_RETURN': 'This is a test 15:11 25.11.2018'}
        ex : {'status': False, 'ERROR': 'Not found'}
    """
    async with websockets.connect(ws_address,ssl = ssl_context) as websocket:
        
        challenge = await websocket.recv()

        tag = computeTag(txid,mackey,challenge)

        message = json.dumps({ "txid" : txid , "TAG" : tag})
        
        await websocket.send(message)
        
        response = await websocket.recv()
        response = json.loads(response)
        print(response)
        return response

#Sends a request to the websocket server to post a transaction containing an OP_RETURN
async def sendOPReturn(data,mackey):
    """
        INPUT  data   :  string
               mackey :  hexstring

        OUTPUT response : {status : true/false , txid : hexstring} (JSON)

        ex : {'status': True, 'txid': '8a42bc904c9fcb85ec73bd4b1c6cf5d08f0cec9e97d5ba88b60209174606b314'}
        ex : {'status': False, 'ERROR': 'OP_RETURN > 80 bytes'}
    """
    async with websockets.connect(ws_address,ssl = ssl_context) as websocket:
        
        challenge = await websocket.recv()
        
        tag = computeTag(data,mackey,challenge)
        
        message = json.dumps({"OP_RETURN" : data , "TAG" : tag})
        
        await websocket.send(message)
        
        response = await websocket.recv()
        response = json.loads(response)
        print(response)
        return response

#Sends a request to the websocket server to retrieve the data from an address
async def getWalletInfo(address):
    """
        INPUT  address  : DGB address 

        OUTPUT response : {status : true/false , WalletInfo : {[...]}} (JSON)

        ex : {'status': True, 'WalletInfo': {'addrStr': 'DEk2TrFCjqm8kCV1A1M6gZq9CeBB2XNViE', 'balance': 0.006, 'balanceSat': 600000, 'totalReceived': 0.116, 'totalReceivedSat': 11600000, 'totalSent': 0.11, 'totalSentSat': 11000000, 'unconfirmedBalance': 0, 'unconfirmedBalanceSat': 0, 'unconfirmedTxApperances': 0, 'txApperances': 2, 'transactions': ['60799c7e32951eb879dd51386a208dd45ea8989e702fcedcbbee181e7caa363c', '8d1d5ab12d85e72180426b0f7b966d6aff04eeae67e1160dc4566412c01f42ff']}}
        ex : {'status': False, 'ERROR': 'INVALID ADDRESS'}
    """
    async with websockets.connect(ws_address,ssl = ssl_context) as websocket:

        challenge = await websocket.recv()
        
        tag = computeTag(wallet, mackey,challenge)
        
        message = json.dumps({"Wallet" : wallet, "TAG" : tag})

        await websocket.send(message)
        
        response = await websocket.recv()
        
        response = json.loads(response)
        
        #if "WalletInfo" in response:
        #    walletinfo = response["WalletInfo"]
        #    print('Address : {}'.format(walletinfo['addrStr']))
        #    print('Balance : {}'.format(walletinfo['balance']))
        #    print('Txid number {}'.format(walletinfo['txApperances']))
        #    for tx in walletinfo['transactions']:
        #        print(tx)
        print(response)
        return response

def getwalletinfo(address):
    """
        INPUT  address  : DGB address

        OUTPUT : error or json object with walletinfos

    """
    r = requests.get(explorerUrl + "/addr/" + address)
    if r.status_code == 200:
        return r.json()
    else:
        return {'error' : r.text}

def getUTXOs(address):
    """
        INPUT  address  : DGB address
        OUTPUT : error or json object with walletinfos
    """
    r = requests.get(explorerUrl + "/addr/" + address + "/utxo" )
    if r.status_code == 200:
        return r.json()
    else:
        return {'error' : r.text}

def getTxData(txid):
    """
        INPUT  address  : DGB address
        OUTPUT : error or json object with rawtx
    """
    r = requests.get(explorerUrl + "/tx/" + txid)   
    if r.status_code == 200:
        return r.json()
    else:
        return {'error' : r.text}

def getOpData(txid):
    """
        INPUT  address  : DGB address
        OUTPUT : {time : integer, OP_RETURN : bytes}
    """
    tx = getTxData(txid)

    if tx == 'Not found':
        return tx
    
    else:

        out = {}
        out['time'] = tx['time']
        out['OP_RETURN'] = b''
        
        #Looks for the OP_RETURN
        for data in tx['vout']:
            if 'scriptPubKey' in data:
                if 'asm' in data['scriptPubKey']:
                    OP = data['scriptPubKey']['hex']
                    if OP[:2] == '6a':
                        out['OP_RETURN'] = unhexlify(OP[4:])

        return out


#asyncio.get_event_loop().run_until_complete(getOPReturn(txid,mackey))
#asyncio.get_event_loop().run_until_complete(sendOPReturn(data,mackey))
#asyncio.get_event_loop().run_until_complete(getWalletInfo(wallet))
