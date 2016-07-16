from base64 import b64encode, b64decode
from binascii import hexlify

from hashlib import sha256
import os.path
from os import urandom
from timeit import default_timer as timer
from collections import defaultdict
from traceback import print_stack, print_exc
from twisted.test.proto_helpers import StringTransport

import rscoin
from rscoin.rscservice import RSCFactory, load_setup, get_authorities
from rscoin.rscservice import package_query, unpackage_query_response, \
                        package_commit, package_issue, unpackage_commit_response, \
                        RSCProtocol
from tests.test_rscservice import sometx
from rscoin.logging import RSCLogEntry, RSCLogger, decode_jason_to_log_entry, \
                           encode_log_entry_to_jason
from py._path.svnwc import LogEntry
                        

def test_QueryLogEntry_serialize(sometx):
    (factory, instance, tr), (k1, k2, tx1, tx2, tx3) = sometx

    H, dataString, _ = package_query(tx3, [tx1, tx2], [k1, k2]) 
    #??? H is hash digest of quired data
    items = dataString.split(" ")
    bundle_size = int(items[1])

    try:
        items = items[2:2+bundle_size]
        H, data = RSCProtocol.parse_Tx_bundle( bundle_size, items)
        
    except Exception as e:
        print_exc()
        return
    
    logEntry = RSCLogEntry(data,"Query_Success") 
    
    logger = RSCLogger()
    logger.write_log(logEntry)
    #jasonString = logger.query_log(logEntry.utcTimestamp)
    jasonString = logger.query_log_by_processedTxId(logEntry.processedTx.id())
    
    logEntry2 = decode_jason_to_log_entry(jasonString)
    
    assert logEntry.parentTx == logEntry2.parentTx
    assert logEntry.processedTx.id() == logEntry2.processedTx.id()
    
def test_CommitLogEntry_serialize(sometx):
    # query phase
    (factory, instance, tr), (k1, k2, tx1, tx2, tx3) = sometx

    # Check the list is up to date
    for ik in tx3.get_utxo_in_keys():
        assert ik in factory.db

    H, dataString, dataCoreString = package_query(tx3, [tx1, tx2], [k1, k2]) 
    
    instance.lineReceived(dataString)
    response = tr.value()
    
    _, k, s, hashhead, seqStr = unpackage_query_response(response)
    
    new_H = sha256(" ".join(  dataCoreString
                            + [hashhead] 
                            + [seqStr])
                   ).digest()
    #... notice in sometx, there is only one factory playing mintette
    #... factory.key.pub.export( EcPt.POINT_CONVERSION_UNCOMPRESSED ) == k  
    assert factory.key.verify(new_H, s)
    
    # commit phase
    tr.clear()
    
    # items here is the same with dataCore
    dataString2 = package_commit(dataCoreString, [(k, s, hashhead, seqStr)])
    
    items = dataString2.split()
    try:
        bundle_size = int(items[1])    

        extras = items[2+bundle_size:] 
        items = items[2:2+bundle_size]
        
        # Specific checks
        assert len(items[2+bundle_size:]) == 0

        auth_keys, auth_sigs = [], []
        hashheads, seqStrs = [], []

        while len(extras) > 0:
            auth_keys += [ b64decode(extras.pop(0)) ]
            auth_sigs += [ b64decode(extras.pop(0)) ]
            hashheads += [ b64decode(extras.pop(0)) ]
            seqStrs   += [ b64decode(extras.pop(0)) ]
        assert len(extras) == 0
        
        
        
        H, data = RSCProtocol.parse_Tx_bundle( bundle_size, items)
        (mainTx, otherTx, keys, sigs) = data
                        
    except:
        print_exc()
        return

    data = (H, mainTx, otherTx, keys, sigs, 
            auth_keys, auth_sigs, hashheads, seqStrs, items)
    
    
    logEntry = RSCLogEntry(data, action = "Commit_Success", lampClock = "30" )
    
    
       
    logger = RSCLogger()
    logger.write_log(logEntry)
    #jasonString = logger.query_log(logEntry.utcTimestamp)
    
    
    jasonString = logger.query_log_by(logEntry.processedTx.id(), logEntry.action)  
    logEntry2 = decode_jason_to_log_entry(jasonString)
    
    
        
    assert logEntry.processedTx.id() == logEntry2.processedTx.id()
    assert logEntry.processedTx == logEntry2.processedTx
#    assert logEntry.authKeys == logEntry2.authKeys
#    assert logEntry.authKeys == logEntry2.authKeys
#    assert logEntry.hashheads == logEntry.hashheads

def test_hash_head(sometx):
    (factory, instance, tr), (k1, k2, tx1, tx2, tx3) = sometx

    # Check the list is up to date
    for ik in tx3.get_utxo_in_keys():
        assert ik in factory.db

    H, dataString, _ = package_query(tx3, [tx1, tx2], [k1, k2]) 
    #... H is hash digest of quired dataCore
    #... where data is serialized (mainTx, otherTx, keys, sigs)

    instance.lineReceived(dataString)
    response = tr.value()
    tr.clear()
    
    instance.lineReceived(dataString)
    response = tr.value()
    tr.clear()
    
    instance.lineReceived(dataString)
    response = tr.value()
    tr.clear()

    
    items = dataString.split(" ")
    bundle_size = int(items[1])

    try:
        items = items[2:2+bundle_size]
        H, data = RSCProtocol.parse_Tx_bundle( bundle_size, items)
        
    except Exception as e:
        print_exc()
        return
    
    
    logEntry = RSCLogEntry(data, "Query_Success")
    
    
    tmpHashhead = sha256(logEntry.serialize()+"").digest()
    tmpHashhead = sha256(logEntry.serialize()+tmpHashhead).digest()
    tmpHashhead = sha256(logEntry.serialize()+tmpHashhead).digest()
    
    assert tmpHashhead == factory.get_hash_head()

def test_TxQuery_signature(sometx):
    (factory, instance, tr), (k1, k2, tx1, tx2, tx3) = sometx

    # Check the list is up to date
    for ik in tx3.get_utxo_in_keys():
        assert ik in factory.db

    H, dataString, _ = package_query(tx3, [tx1, tx2], [k1, k2]) 
    
    
    items = dataString.split(" ")
    bundle_size = int(items[1])
    
    
    try:
        items = items[2:2+bundle_size]
        H, data = RSCProtocol.parse_Tx_bundle( bundle_size, items)
    # items here already become the b64encoded string of  /
    # serialized (tx3, [tx1, tx2], [k1, k2])  
    except Exception as e:
        print_exc()
        return
    instance.lineReceived(dataString)
    response = tr.value()
    tr.clear()
    
    
    instance.lineReceived(dataString)
    response = tr.value()
    tr.clear()
    
    instance.lineReceived(dataString)
    response = tr.value()
    tr.clear()
    

    
    
    _, k, s, hashhead, seqStr = unpackage_query_response(response)
    
    new_H = sha256(" ".join(  items
                            + [hashhead] 
                            + [seqStr])
                   ).digest()
                   
    assert seqStr == "3"
    #... notice in sometx, there is only one factory playing mintette
    #... factory.key.pub.export( EcPt.POINT_CONVERSION_UNCOMPRESSED ) == k  
    assert factory.key.verify(new_H, s)
    
def test_TxCommit(sometx):
    
    # query phase
    (factory, instance, tr), (k1, k2, tx1, tx2, tx3) = sometx

    # Check the list is up to date
    for ik in tx3.get_utxo_in_keys():
        assert ik in factory.db

    H, dataString, dataCoreString = package_query(tx3, [tx1, tx2], [k1, k2]) 
    
    instance.lineReceived(dataString)
    response = tr.value()
    
    _, k, s, hashhead, seqStr = unpackage_query_response(response)
    
    new_H = sha256(" ".join(  dataCoreString
                            + [hashhead] 
                            + [seqStr])
                   ).digest()
    #... notice in sometx, there is only one factory playing mintette
    #... factory.key.pub.export( EcPt.POINT_CONVERSION_UNCOMPRESSED ) == k  
    assert factory.key.verify(new_H, s)
    
    # commit phase
    tr.clear()
    
    # items here is the same with dataCore
    dataString2 = package_commit(dataCoreString, [(k, s, hashhead, seqStr)])
    instance.lineReceived(dataString2)
    response = tr.value()
    
    
    flag, pub, sig, hashhead, seqStr = unpackage_commit_response(response)
    
    new_h = sha256(" ".join(dataCoreString
                            + [hashhead] 
                            +[seqStr])).digest()
    
    assert factory.key.verify(new_h, sig)
    k3 = rscoin.Key(pub)
    assert k3.verify(new_h, sig)
    
    
    
    
