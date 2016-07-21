from base64 import b64encode, b64decode
from binascii import hexlify
from struct import pack, unpack

from json import loads
from bisect import bisect_left
# import bsddb

from future.moves import dbm

from traceback import print_stack, print_exc
from hashlib import sha256
from os.path import join

from petlib.ec import EcPt

from twisted.internet import protocol
from twisted.protocols.basic import LineReceiver
from twisted.python import log

import rscoin
from datetime import datetime 
from pymongo import MongoClient
from py._path.svnwc import LogEntry

import pickle


class RSCLogEntry:
    """Represents a log entry that will be stored in the logging database"""
    def __init__(self, data = None, action = None, sig = None, lampClock = None):
        """ Make a key given a public or private key in bytes """
        """ sig is the signature from the current mintette"""
        self.ser = None
        if action == None:
            self.processedTx = None
            self.parentTx = None
            self.lampClock = None
            self.action = None
        
            """
            inputAddrKeys are the public keys that correspond to output addr
            in the input transactions
            """
            self.inputAddrKeys = None  
            self.inputSigs = None
            self.hashhead = None
            
            return 
        
        self.utcTimestamp = datetime.utcnow() 
        #notice unlike mainTx, otherTx is unparsed data bytes
        
        """
        mainTx type: Tx
        otherTx type: [Tx.serialize]
        keys type: 
        sigs : 
        """
        
        
        if action == "Commit_Success":
            
            
            (H, mainTx, otherTx, keys, sigs, 
                auth_keys, auth_sigs, hashheads, seqStrs, items) = data
            
            self.processedTx = mainTx
            self.parentTx = otherTx
            self.lampClock = lampClock
            self.action = action
            
            """
            InputAddrKeys are the public keys that correspond to output addr
            in the input transactions
            """
            
            self.inputAddrKeys = keys  
            self.inputSigs = sigs
            
            
            """
            InputAddrKeys are the public keys that correspond to output addr
            in the input transactions
            
            """
            self.authKeys = auth_keys  
            self.authSigs = auth_sigs
            
            
            '''head of hash chain'''
            self.hashheads = hashheads
            self.seqStrs = seqStrs
            
        if action == "Query_Success":
            (mainTx, otherTx, keys, sigs) = data
            
            self.processedTx = mainTx
            self.parentTx = otherTx
            self.lampClock = lampClock
            self.action = action
            
            """
            inputAddrKeys are the public keys that correspond to output addr
            in the input transactions
            """
            self.inputAddrKeys = keys  
            self.inputSigs = sigs
            
            '''head of hash chain'''
            
            self.hashhead = sha256(self.serialize()).digest()
            
    def serialize(self):
        if self.ser is not None:
            return self.ser

        ser = pack("H", len(self.parentTx))
        
        ser += pack("HH", len(self.inputAddrKeys), len(self.inputSigs))
        
        ser += self.processedTx.serialize()
        
        for tx in self.parentTx:
            ser += pack("H", len(tx))
            ser += tx
            
        for addrKey in self.inputAddrKeys:
            ser += pack("H", len(addrKey))
            ser += addrKey
        
        for sig in self.inputSigs:
            ser += sig
        

        self.ser = ser

        return ser
    
    
    
            
            
            
def encode_log_entry_to_jason(logEntry):
    """ Transform the log entry to jason format dict to store into MongoDB """
     
    
    if logEntry.action == "Query_Success" or "Commit_Success":
        # Common fileds for query and commit log entry
        jason_dict= {"date": logEntry.utcTimestamp,
                      "action": logEntry.action,
                      "lampClock": logEntry.lampClock,
                      "processedTxId": b64encode(logEntry.processedTx.id()),
                      }
        
        inputAddrKeys = [ b64encode(key) for key in logEntry.inputAddrKeys ]
        jason_dict.update({"inputAddrKeys" : inputAddrKeys})       
        
        inputSigs = [ b64encode(sig) for sig in logEntry.inputSigs]
        jason_dict.update({"inputSigs" : inputSigs})
        
        
        inputAddrIds = [{"tx_id": b64encode(addrId.tx_id),
                        "pos" : addrId.pos
                        } for addrId in logEntry.processedTx.inTx]
          
        jason_dict.update({"inputAddrIds": inputAddrIds})
        
        outputAddrIds = [{"key_id" : b64encode(outAddrId.key_id),
                         "value": outAddrId.value
                         } for outAddrId in logEntry.processedTx.outTx  ]
        
        jason_dict.update({"outputAddrIds": outputAddrIds})
        
        inputTxs = [b64encode(tx) for tx in logEntry.parentTx]
        
        jason_dict.update({"inputTxs": inputTxs})
        
        jason_dict.update({"processedTx_R": b64encode(logEntry.processedTx.R)})
    
    if logEntry.action == "Commit_Success":
        authKeys = [ b64encode(key) for key in logEntry.authKeys ]
        jason_dict.update({"authKeys" : authKeys})       
        
        authSigs = [ b64encode(sig) for sig in logEntry.authSigs ]
        jason_dict.update({"authSigs" : authSigs})
        
        hashheads = [ b64encode(head) for head in logEntry.hashheads ]
        jason_dict.update({"hashheads" : hashheads})
    
    
    return jason_dict


def decode_jason_to_log_entry(jason_dict):
    
    
    logEntry = RSCLogEntry()
    
    logEntry.action = jason_dict["action"]
    
    if(logEntry.action == "Query_Success" or "Commit_Success"):
    
        logEntry.utcTimestamp = jason_dict["date"]
        
        logEntry.lampClock = jason_dict["lampClock"]
        
        inputAddrIds = [
                        rscoin.InputTx(b64decode(addrId["tx_id"]),int(addrId["pos"])) 
                        
                        for addrId in jason_dict["inputAddrIds"]]
        '''                    
        outputAddrIds = [{"key_id" : b64encode(outAddrId.key_id),
                         "value": outAddrId.value
                         } for outAddrId in logEntry.processedTx.outTx  ]
        
        jason_dict.update({"outputAddrIds": outputAddrIds})
        '''
        outputAddrIds = [
                         rscoin.OutputTx(b64decode(outAddrId["key_id"]), int(outAddrId["value"]))
                         for outAddrId in jason_dict["outputAddrIds"]
                         ]
        
        processedTx = rscoin.Tx(inputAddrIds, outputAddrIds, 
                                b64decode(jason_dict["processedTx_R"]))
        
        logEntry.processedTx = processedTx 
        
        
        inputAddrKeys = [ b64decode(key) for key in jason_dict["inputAddrKeys"] ]
        logEntry.inputAddrKeys = inputAddrKeys      
        
        inputSigs = [ b64decode(sig) for sig in jason_dict["inputSigs"]]
        logEntry.inputSigs = inputSigs
        
        
        
        inputTxs = [b64decode(tx) for tx in jason_dict["inputTxs"]]
        logEntry.parentTx = inputTxs
        
        
    
    if(logEntry.action == "Commit_Success"):
        authKeys = [ b64decode(key) for key in jason_dict["authKeys"] ]
        logEntry.authKeys = authKeys      
        
        authSigs = [ b64decode(sig) for sig in jason_dict["authSigs"]  ]
        logEntry.authSigs = authSigs
        
        hashheads = [ b64encode(head) for head in jason_dict["hashheads"] ]
        logEntry.hashheads = hashheads
         
    
    return logEntry

class RSCLogger:
    def __init__(self, ip = "localhost", port=27017):
        self.client = MongoClient(ip,port)
        self.db = self.client.RSC_Log_Database
        self.collection = self.db.log_collection

    
    def write_log(self, logEntry):
        """   jason_entry = {"date": logEntry.utcTimestamp,
                       "action" : "Query",
                       "processedTxId": b64encode(logEntry.processedTx.id()),
                       
                       "inputTxKeyS": [
                            {"txId": "abc123", "pos":1},
                            {"txId": "abc124", "pos":2},
                            {"txId": "abc125", "pos":6},
                       ],
                       
                       "outputAddrId": [
                            {"keyId":"bbb111", "value": 100},
                            {"keyId":"bbb112", "value": 100},
                            {"keyId":"bbb113", "value": 100}
                                        
                        ]
                       #otherTx: otherTx.searalize()
                       #inputSigs
                       #hashhead
                       #returnedSig
                                             
                       }
                       576c4e2f1d41c8afafec1f91
        """ 
        jason_entry = encode_log_entry_to_jason(logEntry)             
        self.collection.insert(jason_entry)
        
    def query_log_by_time(self, timestamp):
        jason_entry = self.collection.find_one({"date":timestamp})
        
        return jason_entry
    def query_log_by_processedTxId(self, processedTxId):
        jason_entry = self.collection.find_one({"processedTxId":
                                                 b64encode(processedTxId)})
        
        return jason_entry
    def query_log_by_sequenceNum(self, seq ):
        jason_entry = self.collection.find_one({"lampClock": seq})
        return jason_entry
    
    def query_log_by(self, processedTxId, action):
        
        jason_entry = self.collection.find_one({"processedTxId": 
                                                b64encode(processedTxId),
                                                "action":action
                                                
                                                })
        return jason_entry
    
        
            
                    
            
    
    
    
    

    
 
