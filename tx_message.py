import sys, subprocess, json, time, random
import os.path, binascii, struct, string, re, hashlib

# https://bitcoin.org/en/developer-examples#complex-raw-transaction
# https://github.com/ChristopherA/Learning-Bitcoin-from-the-Command-Line/blob/master/06_5_Sending_a_Transaction_with_Data.md

# Simple RPC class
import requests
class RPCHost(object):
    '''Simple class to comunicate with bitcoin based RPC'''
    debug = False
    def __init__(self, url):
        self._session = requests.Session()
        self._url = url
        self._headers = {'content-type': 'application/json'}

    def call(self, rpcMethod, *params):
        payload = json.dumps({"method": rpcMethod, "params": list(params), "jsonrpc": "2.0"})
        if self.debug:
            print("CALL",self._url, payload)
        try:
            response = self._session.post(self._url, headers=self._headers, data=payload)
        except requests.exceptions.ConnectionError:
            raise Exception('Failed to connect for remote procedure call.')

        if not response.status_code in (200, 500):
            raise Exception('RPC connection failure: ' + str(response.status_code) + ' ' + response.reason)

        responseJSON = response.json()

        if 'error' in responseJSON and responseJSON['error'] != None:
            raise Exception('Error in RPC call: ' + str(responseJSON['error']))
        if self.debug: print(responseJSON['result'])
        return responseJSON['result']

# Helper class extracted (and simplified) from pybitcointools for serialize/deserialize
from _functools import reduce
class RawTX(object):

    code_strings = {
        2: '01',
        10: '0123456789',
        16: '0123456789abcdef',
        32: 'abcdefghijklmnopqrstuvwxyz234567',
        58: '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz',
        256: ''.join([chr(x) for x in range(256)])
        }

    def json_is_base(self, obj, base):
        if isinstance(obj, bytes):
            return False

        alpha = self.code_strings[base]
        if isinstance(obj, str):
            for i in range(len(obj)):
                if alpha.find(obj[i]) == -1:
                    return False
            return True
        elif isinstance(obj, (int, float)) or obj is None:
            return True
        elif isinstance(obj, list):
            for i in range(len(obj)):
                if not self.json_is_base(obj[i], base):
                    return False
            return True
        else:
            for x in obj:
                if not self.json_is_base(obj[x], base):
                    return False
            return True

    def json_changebase(self, obj, changer):
        if isinstance(obj, (str, bytes)):
            return changer(obj)
        elif isinstance(obj, (int, float)) or obj is None:
            return obj
        elif isinstance(obj, list):
            return [self.json_changebase(x, changer) for x in obj]
        return dict((x, self.json_changebase(obj[x], changer)) for x in obj)

    def encode(self, val, base, minlen=0):
        base, minlen = int(base), int(minlen)
        code_string = self.code_strings[base]
        result_bytes = bytes()
        while val > 0:
            curcode = code_string[val % base]
            result_bytes = bytes([ord(curcode)]) + result_bytes
            val //= base
        pad_size = minlen - len(result_bytes)

        padding_element = b'\x00' if base == 256 else b'1' \
            if base == 58 else b'0'
        if (pad_size > 0):
            result_bytes = padding_element*pad_size + result_bytes

        result_string = ''.join([chr(y) for y in result_bytes])
        result = result_bytes if base == 256 else result_string

        return result

    def decode(self, string, base):
        if base == 256 and isinstance(string, str):
            string = bytes(bytearray.fromhex(string))
        base = int(base)
        code_string = self.code_strings[base]
        result = 0
        if base == 256:
            def extract(d, cs):
                return d
        else:
            def extract(d, cs):
                return cs.find(d if isinstance(d, str) else chr(d))

        if base == 16:
            string = string.lower()
        while len(string) > 0:
            result *= base
            result += extract(string[0], code_string)
            string = string[1:]
        return result

    def safe_hexlify(self, a):
        return str(binascii.hexlify(a), 'utf-8')

    def from_int_to_byte(self, a):
        return bytes([a])

    def from_byte_to_int(self, a):
        return a

    def num_to_var_int(self, x):
        x = int(x)
        if x < 253: return self.from_int_to_byte(x)
        elif x < 65536: return self.from_int_to_byte(253)+self.encode(x, 256, 2)[::-1]
        elif x < 4294967296: return self.from_int_to_byte(254) + self.encode(x, 256, 4)[::-1]
        else: return self.from_int_to_byte(255) + self.encode(x, 256, 8)[::-1]

    def read_as_int(self, bytez):
        pos[0] += bytez
        return self.decode(tx[pos[0]-bytez:pos[0]][::-1], 256)

    def bytes_to_hex_string(self, b):
        if isinstance(b, str):
            return b
        return ''.join('{:02x}'.format(y) for y in b)

    def deserialize(self, tx):
        if isinstance(tx, str) and re.match('^[0-9a-fA-F]*$', tx):
            #tx = bytes(bytearray.fromhex(tx))
            return self.json_changebase(self.deserialize(binascii.unhexlify(tx)),
                                  lambda x: self.safe_hexlify(x))
        # http://stackoverflow.com/questions/4851463/python-closure-write-to-variable-in-parent-scope
        # Python's scoping rules are demented, requiring me to make pos an object
        # so that it is call-by-reference
        pos = [0]

        def read_as_int(bytez):
            pos[0] += bytez
            return self.decode(tx[pos[0]-bytez:pos[0]][::-1], 256)

        def read_var_int():
            pos[0] += 1

            val = self.from_byte_to_int(tx[pos[0]-1])
            if val < 253:
                return val
            return self.read_as_int(pow(2, val - 252))

        def read_bytes(bytez):
            pos[0] += bytez
            return tx[pos[0]-bytez:pos[0]]

        def read_var_string():
            size = read_var_int()
            return read_bytes(size)

        obj = {"ins": [], "outs": []}
        obj["version"] = read_as_int(4)
        ins = read_var_int()
        for i in range(ins):
            obj["ins"].append({
                "outpoint": {
                    "hash": read_bytes(32)[::-1],
                    "index": read_as_int(4)
                },
                "script": read_var_string(),
                "sequence": read_as_int(4)
            })
        outs = read_var_int()
        for i in range(outs):
            obj["outs"].append({
                "value": read_as_int(8),
                "script": read_var_string()
            })
        obj["locktime"] = read_as_int(4)
        return obj

    def serialize(self, txobj):
        if isinstance(txobj, bytes):
            txobj = bytes_to_hex_string(txobj)
        o = []
        if self.json_is_base(txobj, 16):
            json_changedbase = self.json_changebase(txobj, lambda x: binascii.unhexlify(x))
            hexlified = self.safe_hexlify(self.serialize(json_changedbase))
            return hexlified
        o.append(self.encode(txobj["version"], 256, 4)[::-1])
        o.append(self.num_to_var_int(len(txobj["ins"])))
        for inp in txobj["ins"]:
            o.append( inp["outpoint"]["hash"][::-1] )
            o.append(self.encode(inp["outpoint"]["index"], 256, 4)[::-1])
            o.append(self.num_to_var_int(len(inp["script"]))+( inp["script"] if inp["script"] else bytes()))
            o.append(self.encode(inp["sequence"], 256, 4)[::-1])
        o.append(self.num_to_var_int(len(txobj["outs"])))
        for out in txobj["outs"]:
            o.append(self.encode(out["value"], 256, 8)[::-1])
            o.append( self.num_to_var_int(len(out["script"])) + out["script"] )
        o.append(self.encode(txobj["locktime"], 256, 4)[::-1])
        return reduce(lambda x,y: x+y, o, bytes())


class MessagingTx(object):

    def __init__(self, host, port, user=None, passw=None):
        if user and passw:
            self.rpc = RPCHost('http://%s:%s@%s:%s'%(user,passw,host,str(port)))
        else:
            self.rpc = RPCHost('http://%s:%s'%(host,str(port)))

    def get_wallet(self):
        addr = self.rpc.call('getaccountaddress','')
        priv_key = self.rpc.call('dumpprivkey', addr)
        pub_key = self.rpc.call('validateaddress', addr)['pubkey']
        return {"address":addr, "private_key": priv_key, "public_key": pub_key}

    def is_rpc_ready(self):
        try:
            ready = True
            self.rpc.call('help')
        except:
            ready = False
        return ready

    def get_block_count(self):
        return self.rpc.call('getblockcount') or 0

    def bin_to_hex(self, string):
        return binascii.b2a_hex(string).decode('utf-8')

    def hex_to_bin(self, hex):
        try: raw = binascii.a2b_hex(hex)
        except Exception as e:
            raw = None
            print(e)
        return raw

    def get_block_txns(self, height):
            block = self.rpc.call("getblock", height)
            txns = {}
            for tx in block['tx']:
                txns[tx] = self.rpc.call("gettransaction", tx)
            return txns

    def find_op_return(self, txn_unpacked):
        op_return = []
        for index, output in enumerate(txn_unpacked['vout']):
            asm = output['scriptPubKey']['asm'].split()
            for i in range(len(asm)):
                if asm[i] == "OP_RETURN" and len(asm) > i:
                    op_return.append(asm[i+1])
        return op_return

    def build_txn(self, inputs, outputs, metadata):
         raw_txn = self.rpc.call('createrawtransaction', inputs, outputs)
         #rawtx = RawTX()
         txn = RawTX().deserialize(raw_txn)
         if type(metadata) == str: metadata = metadata.encode('utf-8')
         hex_metadata = self.bin_to_hex(metadata)
         op_return = '6a'
         op_pushdata = '4d'
         metadata_len_little = self.bin_to_hex(struct.pack('<H', len(metadata)))
         payload =  op_return + op_pushdata + metadata_len_little + hex_metadata
         txn['outs'].append({
                 'value': 0,
                 'script': payload
         })
         return RawTX().serialize(txn)

    def select_inputs(self, total_amount):
        # List and sort unspent inputs by priority
        unspent_inputs = self.rpc.call("listunspent")
        if not isinstance(unspent_inputs, list):
                return {'error': 'Could not retrieve list of unspent inputs'}
        unspent_inputs.sort(key=lambda unspent_input:
                        unspent_input['amount']*unspent_input['confirmations'],
                        reverse=True)
        # Identify which inputs should be spent
        inputs_spend = []
        input_amount = 0
        for unspent_input in unspent_inputs:
            inputs_spend.append({'txid':unspent_input['txid'],'vout':unspent_input['vout']})
            input_amount += unspent_input['amount']
            if input_amount >= total_amount:
                break # stop when we have enough
        if input_amount < total_amount:
            return {'error': 'Not enough funds are available to cover the amount and fee'}
        return {'inputs': inputs_spend,'total': input_amount}

    def get_tx_data(self, txid):
        raw = self.rpc.call("getrawtransaction", txid)
        return self.rpc.call("decoderawtransaction", raw)

    def send_raw_tx(self, data):
        if not data: return {'error': 'send_raw_tx data cannot be empty'}
        signed_tx = self.rpc.call("signrawtransaction", data)
        if not ('complete' in signed_tx and signed_tx['complete']):
            return {'error': 'Could not sign the transaction'}
        return {'txid': self.rpc.call("sendrawtransaction", signed_tx['hex'])}

    def get_received_unspent_txs(self):
        unspent = self.rpc.call("listunspent")
        my_txns = []
        for t in unspent:
            if not t['generated'] and t['spendable']:
                my_txns.append(t)
        return my_txns

    def get_my_txns(self, count, send=True, recv=True):
        txns = self.rpc.call("listtransactions", "*", count)
        my_txns = []
        for t in txns:
            if recv and t['category'] == 'receive':
                my_txns.append(t)
            if send and t['category'] == 'send':
                my_txns.append(t)
        return my_txns

    def lock_tx(self, txid, vout=0):
        return self.rpc.call('lockunspent', False, [{'txid':txid,'vout':vout}])

    def unlock_tx(self, txid, vout=0):
        return self.rpc.call('lockunspent', True, [{'txid':txid,'vout':vout}])

    def lock_all(self, unless_txid=[]):
        unspent = self.get_received_unspent_txs()
        for tx in unspent:
            if tx['txid'] in unless_txid: continue
            self.lock_tx(tx['txid'], int(tx['vout']))

    def unlock_all(self):
        locked = self.rpc.call('listlockunspent')
        for tx in locked:
            self.unlock_tx(tx['txid'], int(tx['vout']))

    def create_tx(self, addr, fee, amount, msg=None):
        output_amount = amount + fee
        inputs_spend = self.select_inputs(output_amount)
        if 'error' in inputs_spend:
            print(inputs_spend['error'])
            if 'error' in inputs_spend:
                print(inputs_spend['error'])
                return None
            return None
        change_amount = round(inputs_spend['total'] - output_amount, 8)
        change_address = self.rpc.call('getrawchangeaddress')
        outputs = {addr: amount, change_address: change_amount}
        return self.build_txn(inputs_spend['inputs'], outputs, msg)

    def get_messages(self, count=10, unspent=False):
        messages = []
        my_txns = self.get_received_unspent_txs() if unspent else self.get_my_txns(count, send=False)
        for t in my_txns:
            op_ret = self.find_op_return(self.get_tx_data(t['txid']))
            for msg in op_ret:
                messages.append({
                    'message': self.hex_to_bin(msg),
                    'tx':t
                    })
        return messages

    def send_message(self, addr, msg, amount, fee):
        tx = self.create_tx(addr, fee, amount, msg)
        return self.send_raw_tx(tx)
