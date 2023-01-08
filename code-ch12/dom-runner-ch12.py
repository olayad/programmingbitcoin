#!/usr/bin/env python3

import time

from block import Block
from bloomfilter import BloomFilter
from ecc import PrivateKey
from helper import hash256, little_endian_to_int, encode_varint, read_varint, decode_base58, SIGHASH_ALL
from merkleblock import MerkleBlock
from network import (
    GetDataMessage,
    GetHeadersMessage,
    HeadersMessage,
    NetworkEnvelope,
    SimpleNode,
    TX_DATA_TYPE,
    FILTERED_BLOCK_DATA_TYPE,
)
from script import p2pkh_script, Script
from tx import Tx, TxIn, TxOut

last_block_hex = '0000000000000024a214945dd448e45376891def9a8bf6d7e6c559c9617cf497'

secret = little_endian_to_int(hash256(b'zifu'))  # FILL THIS IN
print(f'secret:{secret}')
private_key = PrivateKey(secret=secret)
addr = private_key.point.address(compressed=False, testnet=True)
h160 = decode_base58(addr)
print(f'Address decoded:{addr}')

target_address = 'mwJn1YPMq7y5F8J3LkC5Hxg9PHyZ5K4cFv'
target_h160 = decode_base58(target_address)
target_script = p2pkh_script(target_h160)
fee = 5000  # fee in satoshis

# connect to testnet.programmingbitcoin.com in testnet mode
node = SimpleNode('testnet.programmingbitcoin.com', testnet=True, logging=False)
# create a bloom filter of size 30 and 5 functions. Add a tweak.
bf = BloomFilter(size=30, function_count=5, tweak=90210)
# add the h160 to the bloom filter
bf.add(h160)
# complete the handshake
node.handshake()
# load the bloom filter with the filterload command
node.send(bf.filterload())

# set start block to last_block from above
start_block = bytes.fromhex(last_block_hex)
# send a getheaders message with the starting block
getheaders = GetHeadersMessage(start_block=start_block)

node.send(getheaders)
# wait for the headers message
headers = node.wait_for(HeadersMessage)
# store the last block as None
last_block = start_block
# initialize the GetDataMessage
getdata = GetDataMessage()
# loop through the blocks in the headers
for b in headers.blocks:
    # check that the proof of work on the block is valid
    if not b.check_pow():
        raise RuntimeError('invalid pow')
    # check that this block's prev_block is the last block
    if last_block != b.prev_block:
        raise RuntimeError('invalid prev_block')
    # add a new item to the get_data_message
    # should be FILTERED_BLOCK_DATA_TYPE and block hash
    getdata.add_data(FILTERED_BLOCK_DATA_TYPE, b.hash())
    # set the last block to the current hash
    last_block = b.hash()
# send the getdata message
node.send(getdata)

# initialize prev_tx and prev_index to None
prev_tx, prev_index = None, None
# loop while prev_tx is None
while prev_tx is None:
# wait for the merkleblock or tx commands
    message = node.wait_for(MerkleBlock, Tx)
    # if we have the merkleblock command
    # check that the MerkleBlock is valid
    if message.command == b'merkleblock':
        if not message.is_valid():
            raise RuntimeError('invalid merkle proof')
    # else we have the tx command
    # set the tx's testnet to be True
    # loop through the tx outs
    else:
        for i, tx_out in enumerate(message.tx_outs):
            if tx_out.script_pubkey.address(testnet=True) == addr:
                # if our output has the same address as our address we found it
                print(f'found: {message.id}, {i}')

# we found our utxo. set prev_tx, prev_index, and tx
# create the TxIn
# calculate the output amount (previous amount minus the fee)
# create a new TxOut to the target script with the output amount
# create a new transaction with the one input and one output
# sign the only input of the transaction
# serialize and hex to see what it looks like
# send this signed transaction on the network
# wait a sec so this message goes through with time.sleep(1)
# now ask for this transaction from the other node
# create a GetDataMessage
# ask for our transaction by adding it to the message
# send the message
# now wait for a Tx response
# if the received tx has the same id as our tx, we are done!