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
import pymongo
from pymongo import MongoClient
from py._path.svnwc import LogEntry
import pickle
from random import randint

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
            authKeys are the public keys of mintettes who own the input txs 
            authSigs are the signatures generated by mintettes who own input txs
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
    
    def get_dataCoreStrList(self):
        
        assert self.action == "Query_Success" or "Commit_Success" 
        
        items = [ self.processedTx.serialize()]
        
        for txi in self.parentTx:
            items += [txi]
        
        for k in self.inputAddrKeys:
            items += [k]
            
        for sig in self.inputSigs:
            items += [sig]
            
        dataCore = map(b64encode, items)
    
        return dataCore    
            
    def get_commit_data(self):
        
        assert self.action == "Commit_Success"
        
        mainTx = self.processedTx
        
        if len(mainTx.inTx) > 0:
            otherTx = self.parentTx
            keys = self.inputAddrKeys
            sigs = self.inputSigs
            
            auth_keys = self.authKeys
            auth_sigs = self.authSigs
            hashheads = self.hashheads
            seqStrs = self.seqStrs
            
        elif len(mainTx.inTx) == 0: 
            otherTx = []
            keys = self.inputAddrKeys
            sigs = self.inputSigs
            
            auth_keys = []
            auth_sigs = []
            hashheads = []
            seqStrs = []        
    
        
        items = [mainTx.serialize()]
        
        for tx in otherTx:
            items += [tx]
        
        for k in keys:
            items += [k] 
            
        for sig in sigs:
            items += [sig]
        
        dataCore = map(b64encode, items)
        H = sha256(" ".join(dataCore)).digest()
        
        return (H, mainTx, otherTx, keys, sigs,
                 auth_keys, auth_sigs, hashheads, seqStrs, dataCore)
        
    def get_query_data(self):
        assert self.action == "Query_Success"
        mainTx = self.processedTx
        otherTx = self.parentTx
        keys = self.inputAddrKeys
        sigs = self.inputSigs
        
        return (mainTx, otherTx, keys, sigs)
            
    def serialize(self):
        
        if self.ser is not None:
            return self.ser
        
        if self.action == "Query_Success":
            ser = pack("H", len(self.action))
            
            ser += pack("13s", str(self.action))
            ser += pack("H", len(self.parentTx))
            
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
        if self.action == "Commit_Success":
            ser = pack("H", len(self.action))
            ser += pack("14s", str(self.action))
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
            
            for authKey in self.authKeys:
                ser += authKey
            
            for authSig in self.authSigs:
                ser += authSig
                
            for hh in self.hashheads:
                ser += hh
            for seqStr in self.seqStrs:
                ser += seqStr
            
            self.ser = ser
        
            return ser
            
    
    
            
            
            
def encode_log_entry_to_json(logEntry):
    """ Transform the log entry to jason format dict to store into MongoDB """
     
    
    if logEntry.action == "Query_Success" or "Commit_Success":
        # Common fileds for query and commit log entry
        json_dict= {"date": logEntry.utcTimestamp,
                      "action": logEntry.action,
                      "lampClock": logEntry.lampClock,
                      "processedTxId": b64encode(logEntry.processedTx.id()),
                      }
        
        inputAddrKeys = [ b64encode(key) for key in logEntry.inputAddrKeys ]
        json_dict.update({"inputAddrKeys" : inputAddrKeys})       
        
        inputSigs = [ b64encode(sig) for sig in logEntry.inputSigs]
        json_dict.update({"inputSigs" : inputSigs})
        
        
        inputAddrIds = [{"tx_id": b64encode(addrId.tx_id),
                        "pos" : addrId.pos
                        } for addrId in logEntry.processedTx.inTx]
          
        json_dict.update({"inputAddrIds": inputAddrIds})
        
        outputAddrIds = [{"key_id" : b64encode(outAddrId.key_id),
                         "value": outAddrId.value
                         } for outAddrId in logEntry.processedTx.outTx  ]
        
        json_dict.update({"outputAddrIds": outputAddrIds})
        
        inputTxs = [b64encode(tx) for tx in logEntry.parentTx]
        
        json_dict.update({"inputTxs": inputTxs})
        
        json_dict.update({"processedTx_R": b64encode(logEntry.processedTx.R)})
    
    if logEntry.action == "Commit_Success":
        authKeys = [ b64encode(key) for key in logEntry.authKeys ]
        json_dict.update({"authKeys" : authKeys})       
        
        authSigs = [ b64encode(sig) for sig in logEntry.authSigs ]
        json_dict.update({"authSigs" : authSigs})
        
        hashheads = [ b64encode(head) for head in logEntry.hashheads ]
        json_dict.update({"hashheads" : hashheads})
        
        seqs = [ int(seq) for seq in logEntry.seqStrs ]
        json_dict.update({"seqs" : seqs})
    
    
    return json_dict


def decode_json_to_log_entry(jason_dict):
    
    
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
        
        hashheads = [ b64decode(head) for head in jason_dict["hashheads"] ]
        logEntry.hashheads = hashheads
        
        seqStrs = [str(seq) for seq in jason_dict["seqs"] ]
        logEntry.seqStrs = seqStrs
         
    
    return logEntry



class RSCLogger:
    def __init__(self, ip = "localhost", port=27017):
        self.client = MongoClient(ip,port)
        self.db = self.client.RSC_Log_Database
        self.collection = self.db.log_collection
        self.db.collection.create_index([("lampClock", pymongo.ASCENDING)])
        #self.db.collection.create_index([("inputAddrIds", pymongo.ASCENDING)])
    
    def query_total_number(self):   
        cursor = self.collection.find({})
        return cursor.count()
    def query_log_by_end_seq(self, seq):
        cursor = self.collection.find({"lampClock":{"$lte":seq}}) \
                       .sort("lampClock",pymongo.ASCENDING)
        
        logEntries = []
        for json_string in cursor:
            logEntries += [decode_json_to_log_entry(json_string)]                                                    
        return logEntries

        return cursor               
    def write_log(self, logEntry): 
        json_entry = encode_log_entry_to_json(logEntry)             
        self.collection.insert(json_entry)
        
    def query_log_by_time(self, timestamp):
        json_entry = self.collection.find_one({"date":timestamp})
        
        return json_entry
    def query_log_by_processedTxId(self, processedTxId):
        json_entry = self.collection.find_one({"processedTxId":
                                                 b64encode(processedTxId)})
        
        return json_entry
    def query_log_by_sequenceNum(self, seq ):
        json_entry = self.collection.find_one({"lampClock": seq})
        return json_entry
    
    def query_log_by_inputAddrId(self, tx_id, pos):
        """
            inputAddrIds = [{"tx_id": b64encode(addrId.tx_id),
                        "pos" : addrId.pos
                        } for addrId in logEntry.processedTx.inTx]
          
            json_dict.update({"inputAddrIds": inputAddrIds})
        """
        logCursor = self.collection.find({ "inputAddrIds" : 
                                           { "$elemMatch" : { "tx_id" : b64encode(tx_id),
                                                              "pos": pos
        
                                                             } }});
        logEntries = []
        for json_string in logCursor:
            logEntries += [decode_json_to_log_entry(json_string)]                                                    
        return logEntries

    def verify_log(self, seq, hashhead):
        """
        Given the sequence number and hash head 
        Verify log items within sequence number area: 1-seq 
        """
        logEntries = self.collection.find({"lampClock":{"$lte":seq}}) \
                       .sort("lampClock",pymongo.ASCENDING)
        
        for json_string in logEntries:
            logEntry = decode_json_to_log_entry(json_string)
            if logEntry.lampClock == 1:
                hash_head = sha256(logEntry.serialize()+"").digest()
            else:
                hash_head = sha256(logEntry.serialize()+hash_head).digest()
        
        return hash_head == hashhead
        
    def query_hashhead(self, transactionId, pub, seq):    
        """
        factory.key.pub.export(EcPt.POINT_CONVERSION_UNCOMPRESSED)
        return the unique hash head produced for log[seq] by auditied mintette    
        """
        json_entry = self.collection.find_one({
                                               "processedTxId":b64encode(transactionId),
                                               "action": "Commit_Success",
                                               "seqs": [seq] 
                                               }
                                               )
        
        if(json_entry == None):
            return None
        
        logEntry = decode_json_to_log_entry(json_entry)
        index = logEntry.authKeys.index(pub)
        hashhead = logEntry.hashheads[index]
        sig = logEntry.authSigs[index]
        
        dataCore = logEntry.get_dataCoreStrList()
        
        return hashhead, sig, dataCore
    def query_random_hashhead(self):
        
        
        
        #json_entry = self.collection.find_one({"lampClock":27000})
        #print json_entry
        
        cursor = self.collection.find({"action": "Commit_Success",
                                       "seqs": { "$exists": True, "$not": {"$size": 0}}
                                       })
        #print cursor.count()
        
        if (cursor.count() == 0):
            return None
        if(cursor.count()==1):
            randomIndex = 0;
        
        else:
            randomIndex= randint(0, cursor.count()-1)
        
       
        
        json_entry = cursor[randomIndex]
        
        logEntry = decode_json_to_log_entry(json_entry)
        
        randomIndex_2 = randint(0, len(logEntry.authKeys)-1)
        
        
        
        hashhead = logEntry.hashheads[randomIndex_2]
        pub = logEntry.authKeys[randomIndex_2]
        sig = logEntry.authSigs[randomIndex_2] 
        seqStr = logEntry.seqStrs[randomIndex_2]
        dataCore = logEntry.get_dataCoreStrList() 
        
        return (hashhead, pub, sig, seqStr, dataCore)
class Auditor:
    def __init__(self, directory, special_key ):
        self.special_key = special_key
        self.logger = None
        self.directory = directory

    def connect_to_log_db(self, ip = "localhost", port=27017):
        self.logger = RSCLogger(ip, port)
    
    def audit_logEntry(self, logEntry, audited_pub_id):
        
        res = False
        
        if logEntry.action == "Commit_Success":
            data = logEntry.get_commit_data()
            res = self.check_commit_action(data, audited_pub_id)
            print "audit finish "+ logEntry.action + str(logEntry.lampClock)
        elif logEntry.action == "Query_Success":
            data = logEntry.get_query_data()
            res = self.check_query_action(data, audited_pub_id)
            print "audit finish "+ logEntry.action + str(logEntry.lampClock)
        return res
    def check_commit_action(self, data, audited_pub_id):
        H, mainTx, otherTx, keys, sigs, auth_pub, auth_sig, hashheads, seqStrs, items \
        = data
    
        ik = mainTx.id()
        lst = get_authorities(self.directory, ik)
        should_handle = (audited_pub_id in lst)
        
        if not should_handle:
            return False
        
        # First check all signatures
        all_good = True
        pub_set = []
        
        # hh is hash head, while zip set is null, this part checks is skipped
        for pub, sig, hh, s in zip(auth_pub, auth_sig, hashheads, seqStrs):
            key = rscoin.Key(pub)
            pub_set += [ key.id() ]
            
            new_H = sha256(" ".join(  items
                            + [hh] 
                            + [s])
                   ).digest()
            
            all_good &= key.verify(new_H, sig)

        if not all_good:
            return False
        
        all_good = mainTx.check_transaction(otherTx, keys, sigs, masterkey=self.special_key)
        if not all_good:
            return False

        pub_set = set(pub_set)
        mid = mainTx.id()
        inTxo = mainTx.get_utxo_in_keys()
        for itx in inTxo:
            ## Ensure we have a Quorum for each input
            aut = set(get_authorities(self.directory, itx))
            all_good &= (len(aut & pub_set) > len(aut) / 2) 

        if not all_good:
            log.msg('Failed Tx Authority Consensus')
            return False
        
        return all_good
    def check_query_action(self, data, audited_pub_id):
        mainTx, otherTx, keys, sigs = data
        mid = mainTx.id()
        inTxo = mainTx.get_utxo_in_keys()

        # Check that at least one Input is handled by this server
        should_handle_ik = []
        for ik in inTxo:
            lst = get_authorities(self.directory, ik)
            if audited_pub_id in lst:
                should_handle_ik += [ ik ]

        if should_handle_ik == []:
            #print("Not in ID range.")
            return False
        
        all_good = mainTx.check_transaction(otherTx, keys, sigs)
        if not all_good:
            print("Failed TX check")
            return False
        all_good = True
        for ik in should_handle_ik:
            all_good &= self.check_double_spending(ik, mid)
        
        return all_good
            
    def check_double_spending(self, inTx_Key, processed_tx_id):
        """ inTx_keys = Tx.get_utxo_in_keys"""
        tx_id, pos= unpack("32sI",inTx_Key)
        """
            inputAddrIds = [{"tx_id": b64encode(addrId.tx_id),
                        "pos" : addrId.pos
                        } for addrId in logEntry.processedTx.inTx]
          
            json_dict.update({"inputAddrIds": inputAddrIds})
        """
        logEntries = self.logger.query_log_by_inputAddrId(tx_id, pos)
        
        assert len(logEntries) > 1
        
        earliest_query_seq = None
        latest_commit_seq = None 
        
        noDoubleSpent = True
        committed = False  # input_transaction must have been committed
        for entry in logEntries:
            noDoubleSpent&= (entry.processedTx.id() == processed_tx_id)
            if entry.action == "Query_Success":
                if earliest_query_seq == None:
                    earliest_query_seq = entry.lampClock
                elif earliest_query_seq > entry.lampClock:
                        earliest_query_seq  = entry.lampClock
                        
            if entry.action == "Commit_Success":
                committed = True
                if latest_commit_seq == None:
                    latest_commit_seq = entry.lampClock
                elif latest_commit_seq < entry.lampClock:
                    latest_commit_seq = entry.lampClock
                    
        noDoubleSpent &= committed
        #noDoubleSpent &= (latest_commit_seq < earliest_query_seq)
        
        return noDoubleSpent
    
    
    
    def audit_log(self, pub_id, ip, logDBport, hashhead, seq):
        self.connect_to_log_db(ip, logDBport)
        
        valid_log = True
        logEntries = self.logger.collection.find({"lampClock":{"$lte":seq}}) \
                       .sort("lampClock",pymongo.ASCENDING)
         
        for json_string in logEntries:
            logEntry = decode_json_to_log_entry(json_string)
            if logEntry.lampClock == 1:
                hash_head = sha256(logEntry.serialize()+"").digest()
            else:
                assert hash_head != None # the if operation must have been executed
                hash_head = sha256(logEntry.serialize()+hash_head).digest()
                
            valid_log &= self.audit_logEntry(logEntry, pub_id)
        valid_log &= (hash_head == hashhead)
        
    
        return valid_log
    
    def start_online_audit(self):
        logDBport = 27017
        all_good = True
        
        while(True):
            for (kid, ip, port) in self.directory:
                
                logger = RSCLogger(ip,logDBport)
                hashhead_bundle = logger.query_random_hashhead()
                
                if(hashhead_bundle == None):
                    continue;
                
                (hashhead, pub, sig, seqStr, dataCore) = hashhead_bundle
                    
                pub_key = rscoin.Key(pub)
                found_audited_mintette = False
                
                
                for (kid, ip, port) in self.directory:
                    if pub_key.id() == kid:
                        found_audited_mintette = True
                        break
                    
                if not found_audited_mintette:
                    return False
                
                new_h = sha256(" ".join( dataCore
                        + [hashhead] 
                        +[seqStr])).digest()
                
                assert pub_key.verify(new_h, sig)
                
                all_good &= self.audit_log(kid, ip,logDBport, hashhead, int(seqStr) )
            
        return all_good
                
                    
    
            
                    
            
    
    
def get_authorities(directory, xID, N = 3):
    """ Returns the keys of the authorities for a certain xID """
    d = sorted(directory)
    
    if __debug__:
        for di, _, _ in d:
            assert isinstance(di, str) and len(di) == 32

    if len(d) <= N:  #?????????
        auths = [di[0] for di in d]                                   
    else:
        i = unpack("I", xID[:4])[0] % len(d)
        # i = bisect_left(d, (xID, None, None))
        auths =  [d[(i + j - 1) % len(d)][0] for j in range(N)]


    assert 0 <= len(auths) <= N
    # print N
    return auths
