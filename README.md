# TM-Github

.env file is missing and should have the following format : 

SYMKEY=hexstring
MACKEY=hexstring
PRIVATEKEY=PrivatekeyWIF
allowedIP="["IP0","IP1",...]"

Launch node server with $node -r dotenv/config websocket_server.js