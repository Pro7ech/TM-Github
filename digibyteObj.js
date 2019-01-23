const digibyte = require('digibyte');
const curl = require('curl');
const fs = require('fs');
const https = require('https');
const request = require('request');
const utils = require('./utils');

//External Explorer
const explorerUrl = "https://digiexplorer.info/api"//"http://192.168.1.127:3001/insight-digibyte-api"//;
const marketUrl = "https://api.coinmarketcap.com/v1/ticker/digibyte/";

//Local Explorer
//"http://192.168.1.127:3001/insight-digibyte-api"
//"http://192.168.1.127:3001/insight"


//DIGIBYTE LIB

// General function to check the validity of an address
function isValide(address){
    // address : hex string
    if(digibyte.Address.isValid(address)){
        return true
    }else{
        return false
    }
}

//Creates a privatekey object from a WIF privatekey 
//(same format as the ones that can be exported from the console of the Digibyte Core)
function PrivateKeyfromWIF(privateKey){
    return digibyte.PrivateKey.fromWIF(privateKey)
}


//Derives the public key from the private key
function PrivateKeytoAddress(privateKey){
    return privateKey.toAddress()
}


// Retrieves all the informations about a wallet (address)
function getWalletInfo(address){
    //address : hex string

    return new Promise((resolve, reject) => {

        curl.get(explorerUrl + '/addr/' + address, (error, response, data) => {

            if (error != null || response.statusCode != 200 ){
                var E = {}
                E.error = error
                if(response){E.statusCode = response.statusCode}
                if(data){E.data = data}
                reject(E)

            }else{

                resolve(data);
            };
        });
    });
}

//Retrieves tha balance of the given address
function getWalletbalance(address){
    return new Promise((resolve, reject) =>{
        
        getWalletInfo(address).then(data =>{

            resolve(data.balance)

        }, error => {

            reject(error)
        });
    });
};

// Retrieves the UTXOs of an address
function getUTXOs(address){
    //address : hex string

    return new Promise((resolve, reject) => {

        curl.get(explorerUrl + '/addr/' + address +'/utxo', (error, response, data) => {

            if(error != null || response.statusCode != 200) {
                var E = {}
                E.error = error
                if(response){E.statusCode = response.statusCode}
                if(data){E.data = data}
                reject(E)
            };

            resolve(utils.safelyParseJSON(data));

        });
    });
}

// Creates and formats a transaction
function createTransaction(sourcePrivateKey, sourceAddress, destinations=false, changeAddress=false, fee=false, data=false){
    return new Promise((resolve, reject) => {

        //sourcePrivateKey : hex string

        //sourceAddress : hex string

        // destinations object needs to have this format:
        //  {
        //       "D6qALXSuQdCbsmTLirVJvt8yTLSsk2pHxx":1000,
        //       "D7p5NNFVBQmDc5GySjaf8JCtfsfyUTCn3G":5000
        //  }

        //changeAddress : hex string or False

        //fee : integer

        //data : string or None

        changeAddress = changeAddress || sourceAddress;

        // Checks if there are unspent transactions
        getUTXOs(sourceAddress).then(utxos => {

            if(utxos.length === 0 ){
                reject("The source address has no unspent transactions");
            }

            //Creates a new transaction object
            var transaction = new digibyte.Transaction();

            //Adds all the UTXOs
            for(let i = 0; i < utxos.length; i++){
                transaction.from(utxos[i]);
            }
            
            if(destinations){
            	//Destination address
	            for(let da in destinations) {   
	                transaction.to(da, destinations[da]);
	            }
            }
            
            //Specify fee (optional)
            if(fee) {
                transaction.fee(fee);
            }
            //OP_RETURN (optional)
            if(data) {
                transaction.addData(data);
            }
            //Destination of the unspent outputs
            transaction.change(changeAddress);

            //Signs the transaction
            transaction.sign(sourcePrivateKey);

            resolve(transaction);

        }, error => {

            reject(error);

        });
    });
}

// Function to post a transaction on the Digibyte P2P Network
function sendTransaction(transaction){
    //transaction : object from createTransaction()

    return new Promise((resolve, reject) => {

        request.post({

            "headers" :{ "content-type": "application/json" },
            "url" : explorerUrl + '/tx/send/',
            "body":JSON.stringify( {"rawtx": transaction.serialize()} )

        }, (error, response, data) => {

            if(error != null || response.statusCode != 200){
                var E = {}
                E.error = error
                if(response){E.statusCode = response.statusCode}
                if(data){E.data = data}
                reject(E)

            }else{

                resolve(data);

            };
        });
    });
}

// Function to retrieve the data from a transaction
function getTxData(txid) {
    // txid : hexstring

    return new Promise((resolve, reject) => {

        curl.get(explorerUrl + '/tx/'+ txid, (error, response, data) => {

            if(error != null || response.statusCode != 200){
                var E = {}
                E.error = error
                if(response){E.statusCode = response.statusCode}
                if(data){E.data = data}
                reject(E)
                
            }else{
                
                resolve(JSON.parse(data))
            };
        });
    });
}

// General functiont to retrieve the OP data from a transaction or txid
function getOpData(tx){

    //tx can be a hexexstring (txid) or a transaction (object)
    return new Promise((resolve, reject) => {

        // If tx is a txid HexString, fetches the transaction
        if(typeof tx !== 'object') {

            getTxData(tx).then(result=>{

                var response = {}
                response.time = result.time
                response.OP_RETURN = OPfromtx(result);
                
                resolve(response)

            }, error =>{

                reject(error)

            });

        }else{// If tx is already transaction

            var response = {}
            response.time = result.content.time
            response.OP_RETURN = OPfromtx(tx);
            resolve(response)
        };
    });

    // Retrieves the OP data from the transaction
    function OPfromtx(tx) {

        for(let i in tx.vout){

            var vout = tx.vout[i];
            var data = vout.scriptPubKey.asm || false;
            //6a = OP_RETURN
            if(data && data.substr(0,2) == '6a'){

                return utils.hex2string(data.substr(4));

            };
        };

        return false
    }
}


function anchorData(data, privateKey, address){
    return new Promise((resolve, reject) => {
    	//destinations : JSON.parse('{"' + address + '":' + 600000 + '}')
        createTransaction(  sourcePrivateKey = privateKey,
                            sourceAddress    = address,
                            destinations     = false, 
                            changeAddress    = address,
                            fee              = false,
                            data             = data)

                        .then(transaction => {

                            sendTransaction(transaction).then(result => {
                                
                                resolve(result)

                            //Something bad happened with sendTransaction
                            }, error =>{
                                reject(error)
                            });

                        //Something bad happened with createTransaction
                        }, error =>{
                            reject(error)
                        });
        });
}


module.exports = {
    isValide : isValide,
    PrivateKeyfromWIF : PrivateKeyfromWIF,
    PrivateKeytoAddress : PrivateKeytoAddress,
    getWalletInfo : getWalletInfo,
    getWalletbalance : getWalletbalance,
    createTransaction : createTransaction,
    sendTransaction : sendTransaction,
    getTxData : getTxData,
    getOpData : getOpData,
    anchorData : anchorData 
}