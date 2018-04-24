#!/bin/env python3

from ecies import EC_KEY
from tx_message import MessagingTx
import argparse, time, sys

FEE = 0.00000001

def parse_args():
    parser = argparse.ArgumentParser(description='blockchain tx messaging with encryption')
    parser.add_argument(
            '--host',
            dest='rpc_host',
            type=str,
            default="127.0.0.1",
            help='RPC host to connect')
    parser.add_argument(
            '--port',
            dest='rpc_port',
            type=int,
            default=None,
            help='RPC port to connect')
    parser.add_argument(
            '--auth',
            dest='rpc_auth',
            type=str,
            default=None,
            help='RPC authentication params (username:password)')
    parser.add_argument(
            '-k',
            dest='print_keys',
            action="store_true",
            help='Print wallet keys and exit')
    parser.add_argument(
            '-i',
            dest='keysfile',
            type=str,
            default=None,
            help='File containing own keys (generated with -k)')
    parser.add_argument(
            '-r',
            dest='read',
            type=int,
            default=None,
            help='Read last received messages')
    parser.add_argument(
            '-s',
            dest='send',
            type=str,
            default=None,
            help='Send a message to address')
    parser.add_argument(
            '--fee',
            dest='fee',
            type=float,
            default=None,
            help='Specify fee for transaction')
    parser.add_argument(
            '--text',
            dest='text',
            type=str,
            default=None,
            help='Text to send in message')
    parser.add_argument(
            '--encrypt',
            dest='encrypt',
            action="store_true",
            help='Turn on encryption')
    parser.add_argument(
            '--pubkey',
            dest='dst_pubkey',
            default=None,
            help='If encryption enabled, use destination pubkey')
    return parser.parse_args()

args = parse_args()

def print_and_exit(msg):
        print(msg)
        sys.exit(1)

if not args.rpc_port:
    print_and_exit("RPC port must be specified")

if args.rpc_auth:
    try:
        user = args.rpc_auth.split(':')[0]
        passw = args.rpc_auth.split(':')[1]
    except:
        print_and_exit('Wrong RPC auth syntax, use --auth=user:password')
    mtx = MessagingTx(args.rpc_host,args.rpc_port,user=user,passw=passw)
else:
    mtx = MessagingTx(args.rpc_host,args.rpc_port)


max_wait = 30
while not mtx.is_rpc_ready():
    time.sleep(1)
    max_wait -= 1
    if max_wait <= 0:
        print_and_exit("Cannot connect to RPC after %d seconds" %max_wait)

if args.print_keys:
    print(mtx.get_wallet())
    sys.exit(0)

if args.keysfile:
    try:
        with open(args.keysfile, 'r') as kf:
            raw_keys = kf.read()
        keys = eval(raw_keys)
        privkey = keys['private_key']
        pubkey = keys['public_key']
        address = keys['address']
    except:
        print_and_exit("Wrong keyfile")

if args.read:
    block_count = int(mtx.get_block_count())
    if args.read == 0:
        messages = mtx.get_messages(0,block_count)
    elif args.read > 0:
        messages = mtx.get_messages(block_count-args.read,args.read)
    else:
        print_and_exit("Number of blocks to read cannot be negative")

if args.fee:
    FEE = args.fee

if args.send:
    if not args.text:
        print_and_exit("Missing message content (--text)")
    try:
        addr = args.send.split(':')[0]
        amount = float(args.send.split(':')[1])
    except:
        print_and_exit("Invalid send format, use ADDRESS:AMOUNT")

    print(mtx.send_message(addr, args.text, amount, FEE))
