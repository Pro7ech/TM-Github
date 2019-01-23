const blake = require('blakejs')
const crypto = require('crypto')
const utils = require('./utils')

//Generates a uniform challenge in the provided domaine size
function generateChallenge(size){
	return crypto.randomBytes(size).toString();
}

//Blake2b hash, can be used as a MAC if a key is provided
function blake2b(input, mackey='', outlen = 32) {

    var context = blake.blake2bInit(outlen, utils.hex2Uint8Array(mackey));

    for(let i = 0 ; i<input.length ; i++ ){
        blake.blake2bUpdate(context, utils.utf82Uint8Array(input[i])) 
    }
    
    return  Buffer.from(blake.blake2bFinal(context)).toString('hex')
}

//Checks if blake2b(message,key) == TAG
function checkTAG(message, TAG, mackey=''){
	if(TAG === Buffer.from(blake2b(message,mackey), 'hex').toString('base64')){
		return true
	}
	else{
		return false
	}
}

module.exports = {
    generateChallenge : generateChallenge,
    blake2b : blake2b,
    checkTAG : checkTAG,
}