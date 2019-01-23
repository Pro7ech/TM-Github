//node -r dotenv/config websocket_server.js
//node websocket_server.js

const https = require('https');
const request = require('request');
const WebSocket = require('ws');
const connect = require('connect');
const fs = require('fs');
const crypto = require('./crypto.js');
const DGBO = require('./digibyteObj.js');
const utils = require('./utils');

//Sensitive Variables are loaded in as environment Variables
require('dotenv').load();
const mackey = process.env.MACKEY;
const privateKey = DGBO.PrivateKeyfromWIF(process.env.PRIVATEKEY);
const address = DGBO.PrivateKeytoAddress(privateKey); //Derives the address from the privatekey
const allowedIP = JSON.parse(process.env.allowedIP)

//https server
const port = 3000
const app = connect();
const server = https.createServer({
	cert: fs.readFileSync('certificate.pem'),
	key: fs.readFileSync('key.pem')
},app).listen(port);

//wss server built on top of the https server
const wss = new WebSocket.Server({server : server, path : '/request'})

wss.on('connection', function connection(ws, req) {

	//Retrieves the IP address of the client
	var ip = req.connection.remoteAddress;
	var response = {};

	//Checks if the IP is allowed
	if (allowedIP.includes(ip) != true){
		ws.terminate()
	}

	console.log('ws connected, IP >>' + ip);

	//Message/Action to od when the socket is closed
	ws.on('close', function close() {
		console.log('ws closed, IP >> ' + ip);
	});

	//Connection is automaticaly terminated after the timeout expires if it is not yet closed.
	// state {0, connecting 1 : open, 2: closing, 3: closed}
	setTimeout(function() {	
		if (ws.readyState !== 3){
			response.error = 'request timed out';
			sendandclose(response)
		};
	}, 90000);

	//Challenge (128bits) sent to the client uppon connexion
	challenge = crypto.generateChallenge(16);
	ws.send(challenge);

	//Action to do upon receiving a message
	ws.on('message', function incoming(data) {

		//On message, parse the message
		//Message should be of the form {type:data, TAG:tag}
		data = utils.safelyParseJSON(data);
		
		if(typeof data !== 'object'){

			//If message is not a JSON object
			response.error = 'invalid request'
			sendandclose(response);

		}else if(data.txid && crypto.checkTAG([data.txid,challenge], data.TAG, mackey)){
			//Function to return OP_RETURN data from a transaction of the Digibyte blockchain.
			//Input : txid as hexstring
			//Output : OP_RETURN or nothing found as string
			DGBO.getOpData(data.txid).then(result =>{
			
				response.data = result;
				sendandclose(response);
			
			}, error =>{
				sendandclose(error);
			});
	
		}else if(data.OP_RETURN && crypto.checkTAG([data.OP_RETURN,challenge], data.TAG, mackey)){
			//Function to post OP_RETURN on the Dibibyte blockchain
			//Input : OP_RETURN as string
			//Output : txid or error

			//OP_RETURN can only be of 80 bytes maximum
			if (data.OP_RETURN.length > 80){

				response.error = 'OP_RETURN > 80 bytes';
				sendandclose(response);

			}else{

				DGBO.anchorData(data.OP_RETURN,privateKey,address).then(result => {

					response.data = result;
					sendandclose(response);

				}, error => {
					sendandclose(error);
				});
			};

		}else if(data.Wallet && crypto.checkTAG([data.Wallet,challenge], data.TAG, mackey)){
			//Function to get wallet infos
			//Input : wallet address
			//Output : wallet infos, including all previous txid

			DGBO.getWalletInfo(data.Wallet).then(result =>{

				response.data = result;
				sendandclose(response);

			}, error => {
				sendandclose(error);
			});

		}else{
			//Manages all the invalid requests, terminates the connection and returns an error message.
			response.error = 'invalid request'
			sendandclose(response);
		};
	});

	function sendandclose(data){
		if (ws.readyState !== 3){		
			ws.send(JSON.stringify(data))	
			ws.close();
		};
	};
});

console.log('Server Running on port',port)
