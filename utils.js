//Utility functions

//Avoid crash if the json can't be parsed
function safelyParseJSON(json){
  var parsed
  try {parsed = JSON.parse(json);} 
  catch (e) {return json};
  return parsed 
}

//Converts an utf8 string to an uint8 array
function utf82Uint8Array(string){
  var utf8 = unescape(encodeURIComponent(string))
  var arr = [];
  for (let i = 0; i < utf8.length; i++) {
      arr.push(utf8.charCodeAt(i));
  }
  return arr
}

//Converts an uint8 array to an utf8 string
function uint8Array2utf8(uint8array){
  return String.fromCharCode.apply(null, uint8array);
}

//Converts a hex string to an uint8 array
function hex2Uint8Array(string){
    
  var arr = [];
  for (let i = 0; i < string.length; i+=2) {
      arr.push(parseInt(string.substr(i,2),16));
  }
  return new Uint8Array(arr);
}

//Converts a hex string to an utf8-string
function hex2string(hexx) {
  var hex = hexx.toString();
  var str = '';
  for(let i = 0; i < hex.length; i += 2){
    str += String.fromCharCode(parseInt(hex.substr(i, 2), 16)) 
  };
  return str
}

//Converts a string to a buffer
function string2Buffer(string, type){
  return Buffer.from(string,type)
}

//Converts a buffer to a string
function buffer2String(array, type){
  return array.toString(type);
}


module.exports = {
  safelyParseJSON:safelyParseJSON,
  utf82Uint8Array:utf82Uint8Array,
  hex2string:hex2string,
  uint8Array2utf8:uint8Array2utf8,
  hex2Uint8Array:hex2Uint8Array,
  string2Buffer:string2Buffer,
  buffer2String:buffer2String
}