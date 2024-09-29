#!/usr/bin/env python
# coding: utf-8

# In[1]:


from io import BytesIO
from logging import getLogger
from unittest import TestCase

from helper import (
    encode_varint,
    int_to_little_endian,
    little_endian_to_int,
    read_varint,
)
from op import (
    OP_CODE_FUNCTIONS,
    OP_CODE_NAMES,
)


LOGGER = getLogger(__name__)


# tag::source1[]
class Script:

    def __init__(self, cmds=None):
        if cmds is None:
            self.cmds = []
        else:
            self.cmds = cmds  # <1>
    # end::source1[]

    def __repr__(self):
        result = []
        for cmd in self.cmds:
            if type(cmd) == int:
                if OP_CODE_NAMES.get(cmd):
                    name = OP_CODE_NAMES.get(cmd)
                else:
                    name = 'OP_[{}]'.format(cmd)
                result.append(name)
            else:
                result.append(cmd.hex())
        return ' '.join(result)

    # tag::source4[]
    def __add__(self, other):
        return Script(self.cmds + other.cmds)  # <1>
    # end::source4[]

    # tag::source2[]
    @classmethod
    def parse(cls, s):
#         length = read_varint(s)  # <2>
        length = len(s.getvalue())
        cmds = []
        count = 0
        #print("length: ",length)
        while count < length:  # <3>
            current = s.read(1)  # <4>
            count += 1
            #print("current_byte: ",current)
            current_byte = current[0]  # <5>
            
            if current_byte >= 1 and current_byte <= 75:  # <6>
                n = current_byte
                c1 = s.read(n)
                #print("in if: ",c1)
                cmds.append(c1)
                count += n
            elif current_byte == 76:  # <7>
                data_length = little_endian_to_int(s.read(1))
                c1 = s.read(data_length)
                #print("in 1st elif: ",c1)
                cmds.append(c1)
                count += data_length + 1
            elif current_byte == 77:  # <8>
                data_length = little_endian_to_int(s.read(2))
                c1 = s.read(data_length)
                #print("in 2nd elif: ",c1)
                cmds.append(c1)
                count += data_length + 2
            else:  # <9>
                op_code = current_byte
                #print("in else: ",op_code)
                cmds.append(op_code)
        if count != length:  # <10>
            raise SyntaxError('parsing script failed')
        return cls(cmds)
    # end::source2[]

    # tag::source3[]
    def raw_serialize(self):
        result = b''
        for cmd in self.cmds:
            if type(cmd) == int:  # <1>
                result += int_to_little_endian(cmd, 1)
            else:
                length = len(cmd)
                if length < 75:  # <2>
                    result += int_to_little_endian(length, 1)
                elif length > 75 and length < 0x100:  # <3>
                    result += int_to_little_endian(76, 1)
                    result += int_to_little_endian(length, 1)
                elif length >= 0x100 and length <= 520:  # <4>
                    result += int_to_little_endian(77, 1)
                    result += int_to_little_endian(length, 2)
                else:  # <5>
                    raise ValueError('too long an cmd')
                result += cmd
        return result

    def serialize(self):
        result = self.raw_serialize()
        total = len(result)
        return encode_varint(total) + result  # <6>
    # end::source3[]

    # tag::source5[]
    def evaluate(self, z):
        cmds = self.cmds[:]  # <1>
        stack = []
        altstack = []
        while len(cmds) > 0:  # <2>
            cmd = cmds.pop(0)
            if type(cmd) == int:
                operation = OP_CODE_FUNCTIONS[cmd]  # <3>
                if cmd in (99, 100):  # <4>
                    if not operation(stack, cmds):
                        LOGGER.info('bad op: {}'.format(OP_CODE_NAMES[cmd]))
                        return False
                elif cmd in (107, 108):  # <5>
                    if not operation(stack, altstack):
                        LOGGER.info('bad op: {}'.format(OP_CODE_NAMES[cmd]))
                        return False
                elif cmd in (172, 173, 174, 175):  # <6>
                    if not operation(stack, z):
                        LOGGER.info('bad op: {}'.format(OP_CODE_NAMES[cmd]))
                        return False
                else:
                    if not operation(stack):
                        LOGGER.info('bad op: {}'.format(OP_CODE_NAMES[cmd]))
                        return False
            else:
                stack.append(cmd)  # <7>
        if len(stack) == 0:
            return False  # <8>
        if stack.pop() == b'':
            return False  # <9>
        return True  # <10>
    # end::source5[]


# In[2]:


print("witness_parse")
def witness_parse(wit):
#     print("len: ",len(wit))
    # if annex as the last element in the witness stack
    # print("witness: ",wit)
    if bytes.fromhex(wit[-1])[0:1] == 0X50:
        wit.pop()
    if len(wit) == 0:
        return 0,0,0,0
    elif len(wit) == 1:
        return 1,0,0,0
    else:
        m = 0
        numscr = 0
        #script path spending
        script = wit[-2]
#         print("Script: ",script)
        #analyze script
        script_pubkey = BytesIO(bytes.fromhex(script))
        script_op = Script.parse(script_pubkey)
#         print("script_op: ",script_op)
        scriptele = list(str(script_op).split(" "))
        numchecksig = 1
        poschecksigadd = 0
        for i,ele in enumerate(scriptele):
            if ele.upper() == "OP_CHECKSIGADD":
                numchecksig += 1
                poschecksigadd = i
        if numchecksig > 1:
            # print("numchecksig: ",numchecksig)
            m = scriptele[poschecksigadd+1]
            # print("m: ",m)
        
        controlblock = wit[-1]
        # print("control block: ",controlblock)
        # check if length of control block is valid: 33 + 32m where m[0,128]
        cb_bytes = bytes.fromhex(controlblock)
        # print("length of control block: ",len(cb_bytes))
        leafversion = cb_bytes[0] & 0xfe
#         print("leafversion: ",leafversion)
        cb_bytes = cb_bytes[1:]
#         print("length of control block: ",len(cb_bytes))
        if(len(cb_bytes) % 32 == 0):
#             print("len multiple of 32")
            internalpubkey = cb_bytes[0:32]
            # print("internal pub key: ",internalpubkey)
            numscr = (len(cb_bytes) / 32)
            # print("minimum number of scripts: ",numscr)
        return 2,m,numchecksig,numscr
        
        


# In[ ]:


import psycopg2
import xlsxwriter

try:
    conn = psycopg2.connect("host=localhost dbname=BitcoinBlockchainDB user=postgres password=postgres")
    cur = conn.cursor()
    numTaproot = 0
    numKeyPath = 0
    numScriptPath = 0
    # fetch rows
#     sql_select_query = """select spending_witness from inputs_2021_nov where type = 'witness_v1_taproot' limit 100"""
    sql_select_query = """select spending_witness from inputs_2023_may where recipient like 'bc1p%'"""
#     sql_select_query = """select spending_witness from inputs_2021_nov where spending_transaction_hash = '2eb8dbaa346d4be4e82fe444c2f0be00654d8cfd8c4a9a61b11aeaab8c00b272'"""
    
    cur.execute(sql_select_query)
#     cur = ('0adf90fd381d4a13c3e73740b337b230701189ed94abcb4030781635f035e6d3b50b8506470a68292a2bc74745b7a5732a28254b5f766f09e495929ec308090b01',,'20c13e6d193f5d04506723bd67abcc5d31b610395c445ac6744cb0a1846b3aabaeac20b0e2e48ad7c3d776cf6f2395c504dc19551268ea7429496726c5d5bf72f9333cba519c','c00000000000000000000000000000000000000000000000000000000000000001',)
    i=0
    row = 0
    
    workbook = xlsxwriter.Workbook('result_2023_may.xlsx')
    worksheet = workbook.add_worksheet("My sheet")
    for record in cur:
        numTaproot += 1
        col = 0
#         print("Record: ",record)
        script_sig = list(record)[0].split(",")
        outs,m,n,numscr = witness_parse(script_sig)
        if(outs == 0):
            print("invalid witness")
        elif(outs == 1):
#             worksheet.write(row, col, outs)
            print("key path spending")
            numKeyPath += 1
        elif(outs == 2):
#             worksheet.write(row, col, outs)
            print("script path spending")
            numScriptPath += 1
        # write values in excel
        worksheet.write(row, col, outs)
        col += 1
        worksheet.write(row, col, m)
        col += 1
        worksheet.write(row, col, n)
        col += 1
        worksheet.write(row, col, numscr)
        row += 1
        
    cur.close()
    workbook.close()
    print("numTaproot: ",numTaproot)
    print("numKeyPath: ",numKeyPath)
    print("numScriptPath: ",numScriptPath)
    
except (Exception, psycopg2.DatabaseError) as err:
    print("Error: ",err)
    
finally:
    if conn is not None:
        conn.close()


# In[ ]:





# In[ ]:




