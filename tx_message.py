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


# Helper class for unpacking bitcoin binary data
class Buffer(object):

    def __init__(self, data, ptr=0):
        self.data = data
        self.len = len(data)
        self.ptr = ptr

    def shift(self, chars):
        prefix = self.data[self.ptr:self.ptr+chars]
        self.ptr += chars
        return prefix

    def shift_unpack(self, chars, format):
        unpack=struct.unpack(format, self.shift(chars))
        return unpack[0]

    def shift_varint(self):
        value = self.shift_unpack(1, 'B')
        if value == 0xFF:
            value = self.shift_uint64()
        elif value == 0xFE:
            value = self.shift_unpack(4, '<L')
        elif value == 0xFD:
            value = self.shift_unpack(2, '<H')
        return value

    def shift_uint64(self):
        return self.shift_unpack(4, '<L')+4294967296*self.shift_unpack(4, '<L')

    def used(self):
        return min(self.ptr, self.len)

    def remaining(self):
        return max(self.len-self.ptr, 0)

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
        except: raw = None
        return raw

    def pack_varint(self, integer):
            if integer > 0xFFFFFFFF:
                    packed = "\xFF"+self.pack_uint64(integer)
            elif integer > 0xFFFF:
                    packed = "\xFE"+struct.pack('<L', integer)
            elif integer > 0xFC:
                    packed = "\xFD".struct.pack('<H', integer)
            else:
                    packed = struct.pack('B', integer)
            return packed

    def pack_uint64(self, integer):
            upper=int(integer/4294967296)
            lower=integer-upper*4294967296
            return struct.pack('<L', lower)+struct.pack('<L', upper)

    def unpack_txn_buffer(self, buffer):
            # see: https://en.bitcoin.it/wiki/Transactions
            txn = { 'vin': [], 'vout': [] }
            # small-endian 32-bits
            txn['version'] = buffer.shift_unpack(4, '<L')
            inputs = buffer.shift_varint()
            if inputs > 100000: # sanity check
                    return None
            for _ in range(inputs):
                input={}
                input['txid'] = self.bin_to_hex(buffer.shift(32)[::-1])
                input['vout'] = buffer.shift_unpack(4, '<L')
                length = buffer.shift_varint()
                input['scriptSig'] = self.bin_to_hex(buffer.shift(length))
                input['sequence'] = buffer.shift_unpack(4, '<L')
                txn['vin'].append(input)
            outputs = buffer.shift_varint()
            if outputs > 100000: # sanity check
                return None
            for _ in range(outputs):
               output = {}
               output['value'] = float(buffer.shift_uint64())/100000000
               length = buffer.shift_varint()
               output['scriptPubKey'] = self.bin_to_hex(buffer.shift(length))
               txn['vout'].append(output)
            txn['locktime'] = buffer.shift_unpack(4, '<L')
            return txn

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

    def pack_txn(self, txn):
        binary = b''
        binary += struct.pack('<L', txn['version'])
        binary += self.pack_varint(len(txn['vin']))

        for input in txn['vin']:
                binary += self.hex_to_bin(input['txid'])[::-1]
                binary += struct.pack('<L', input['vout'])
                binary += self.pack_varint(int(len(input['scriptSig'])/2)) # divide by 2 be
                binary += self.hex_to_bin(input['scriptSig'])
                binary += struct.pack('<L', input['sequence'])

        binary += self.pack_varint(len(txn['vout']))

        for output in txn['vout']:
                binary += self.pack_uint64(int(round(output['value']*100000000)))
                binary += self.pack_varint(int(len(output['scriptPubKey'])/2)) # divide by
                binary += self.hex_to_bin(output['scriptPubKey'])

        binary += struct.pack('<L', txn['locktime'])

        return binary

    def build_txn(self, inputs, outputs, metadata, metadata_pos):
         raw_txn = self.rpc.call('createrawtransaction', inputs, outputs)
         raw_tx = self.hex_to_bin(raw_txn)
         txn_unpacked = self.unpack_txn_buffer(Buffer(raw_tx))

         if type(metadata) == str: metadata = metadata.encode('utf-8')
         metadata_len = len(metadata)

         if metadata_len <= 75:
            # length byte + data (https://en.bitcoin.it/wiki/Script)
            payload = bytearray((metadata_len,))+metadata
         elif metadata_len <= 256:
            # OP_PUSHDATA1 format
            payload = '\x4c'.encode('utf-8')+bytearray((metadata_len,)) \
                    +metadata
         else:
            # OP_PUSHDATA2 format
            payload = '\x4d'.encode('utf-8')+bytearray((metadata_len%256,)) \
                    +bytearray((int(metadata_len/256),))+metadata
         #payload = bytearray() + metadata
         metadata_pos = min(max(0, metadata_pos), len(txn_unpacked['vout'])) # constrain to valid values

         txn_unpacked['vout'][metadata_pos:metadata_pos]=[{
                 'value': 0,
                 'scriptPubKey': '6a'+self.bin_to_hex(payload) # here's the OP_RETURN
         }]

         return self.bin_to_hex(self.pack_txn(txn_unpacked))

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
        #print("Available unspend inputs: %s" %len(unspent_inputs))
        for unspent_input in unspent_inputs:
            inputs_spend.append({'txid':unspent_input['txid'],'vout':unspent_input['vout']})

            input_amount += unspent_input['amount']
            if input_amount >= total_amount:
                break # stop when we have enough

        if input_amount < total_amount:
            return {'error': 'Not enough funds are available to cover the amount and fee'}

        # Return the successful result
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

    def get_my_txns(self, count, send=True, recv=True):
        txns = self.rpc.call("listtransactions", "*", count)
        my_txns = []
        for t in txns:
            if recv and t['category'] == 'receive':
                my_txns.append(t['txid'])
            if send and t['category'] == 'send':
                my_txns.append(t['txid'])
        return my_txns

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
        return self.build_txn(inputs_spend['inputs'], outputs, msg, len(outputs))

    def get_messages(self, count=10):
        messages = []
        for t in self.get_my_txns(count, send=False):
            op_ret = self.find_op_return(self.get_tx_data(t))
            for msg in op_ret:
                messages.append(self.hex_to_bin(msg))
        return messages

    def send_message(self, addr, msg, amount, fee):
        tx = self.create_tx(addr, fee, amount, msg)
        return self.send_raw_tx(tx)
