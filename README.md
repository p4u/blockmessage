# BlockMessage

BlockMessage is a tool to send and receive encrypted or plain text messages injected into OP_RETURN Bitcoin based blockchains

As encryption algorithm ECIES is used, so standard BitCoin wallet keys can be used.

```
usage: blockmessage.py [-h] [--host RPC_HOST] [--port RPC_PORT]
                       [--auth RPC_AUTH] [-k] [-i KEYSFILE] [-r READ]
                       [-s SEND] [--fee FEE] [--text TEXT] [--encrypt]
                       [--pubkey DST_PUBKEY]

blockchain tx messaging with encryption

optional arguments:
  -h, --help           show this help message and exit
  --host RPC_HOST      RPC host to connect
  --port RPC_PORT      RPC port to connect
  --auth RPC_AUTH      RPC authentication params (username:password)
  -k                   Print wallet keys and exit
  -i KEYSFILE          File containing own keys (generated with -k)
  -r READ              Read last received messages
  -s SEND              Send a message to address
  --fee FEE            Specify fee for transaction
  --text TEXT          Text to send in message
  --encrypt            Turn on encryption
  --pubkey DST_PUBKEY  If encryption enabled, use destination pubkey
```
