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
from rscoin.rscservice import RSCFactory, load_setup, get_authorities,\
    unpackage_hash_response, package_hashQuery
from rscoin.rscservice import package_query, unpackage_query_response, \
                        package_commit, package_issue, unpackage_commit_response, \
                        RSCProtocol
from tests.test_rscservice import sometx, msg_mass
from rscoin.logging import RSCLogEntry, RSCLogger, decode_json_to_log_entry, \
                           encode_log_entry_to_json, Auditor
from py._path.svnwc import LogEntry
                        
from petlib.ec import EcPt


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
    
    logEntry2 = decode_json_to_log_entry(jasonString)
    
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
    logEntry2 = decode_json_to_log_entry(jasonString)
    
    
        
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

def test_TxQuery_serialize(sometx):
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
    
    
def test_log_verify(msg_mass):
    (sometx, mesages_q) = msg_mass
    (factory, instance, tr) = sometx

    responses = []
    t0 = timer()
    for (tx, data, core) in mesages_q:
        tr.clear()
        instance.lineReceived(data)
        response = tr.value()
        responses += [(tx, data, core, response)]
    t1 = timer()
    print "\nQuery message rate: %2.2f / sec" % (1.0 / ((t1-t0)/(len(mesages_q))))

    ## Now we test the Commit
    t0 = timer()
    for (tx, data, core, response) in responses:
        resp = response.split(" ")
        pub, sig, hashhead, seqStr = map(b64decode, resp[1:])
        assert resp[0] == "OK"
        tr.clear()
        data = package_commit(core, [(pub, sig, hashhead, seqStr)])
        instance.lineReceived(data)
        response = tr.value()
        flag, pub, sig, hashhead, seqStr = unpackage_commit_response(response)
        assert flag == "OK"
    t1 = timer()
    print "\nCommit message rate: %2.2f / sec" % (1.0 / ((t1-t0)/(len(responses))))
    
    
    ## log verification test
    t0 = timer()
    logger = RSCLogger()
    last_queried_tx, data, core = mesages_q[-1]
    authPub = factory.key.pub.export(EcPt.POINT_CONVERSION_UNCOMPRESSED)
    seq =  len(mesages_q)
    
    quired_hashhead, sig, dataCore = logger.query_hashhead(last_queried_tx.id(), authPub, 
                                            seq)
    assert quired_hashhead !=None
    
    new_h = sha256(" ".join( dataCore
                            + [quired_hashhead] 
                            +[str(seq)])).digest()
    
    assert factory.key.verify(new_h, sig)
    
    assert logger.verify_log(len(mesages_q), quired_hashhead) == True
    assert logger.verify_log(int(seqStr), hashhead) == True
    t1 = timer()
    
    ## test hashhead query protocol
    data = package_hashQuery(last_queried_tx, authPub, str(seq))
    tr.clear()
    instance.lineReceived(data)
    response = tr.value()
    quired_hashhead, sig, dataCore = unpackage_hash_response(response)
    assert quired_hashhead !=None
    
    new_h = sha256(" ".join( dataCore
                            + [quired_hashhead] 
                            +[str(seq)])).digest()
    
    assert factory.key.verify(new_h, sig)
    
    assert logger.verify_log(len(mesages_q), quired_hashhead) == True
    assert logger.verify_log(int(seqStr), hashhead) == True
    
    print "\nLog verification rate: %2.2f / sec" % (1.0 / ((t1-t0)/(len(responses))))
    
    
    ## test query by tx_id,pos
    inTx = last_queried_tx.inTx[0]
    tx_id = inTx.tx_id
    pos = inTx.pos
    logEntries = logger.query_log_by_inputAddrId(tx_id, pos)
    assert logEntries != None
    assert len(logEntries) == 2
    
    
    ## test the auditor
    
    auditor = Auditor(factory.directory, factory.special_key)
    auditor.connect_to_log_db("localhost", 27017)
    assert auditor.audit_logEntry(logEntries[0], factory.directory[0][0])
    assert auditor.audit_logEntry(logEntries[1], factory.directory[0][0])
    
       
def test_audit_speed(msg_mass):
    
    
    (sometx, mesages_q) = msg_mass
    (factory, instance, tr) = sometx

    responses = []
    t0 = timer()
    for (tx, data, core) in mesages_q:
        tr.clear()
        instance.lineReceived(data)
        response = tr.value()
        responses += [(tx, data, core, response)]
    t1 = timer()
    #print "\nQuery message rate: %2.2f / sec" % (1.0 / ((t1-t0)/(len(mesages_q))))

    ## Now we test the Commit
    t0 = timer()
    for (tx, data, core, response) in responses:
        resp = response.split(" ")
        pub, sig, hashhead, seqStr = map(b64decode, resp[1:])
        assert resp[0] == "OK"
        tr.clear()
        data = package_commit(core, [(pub, sig, hashhead, seqStr)])
        instance.lineReceived(data)
        response = tr.value()
        flag, pub, sig, hashhead, seqStr = unpackage_commit_response(response)
        assert flag == "OK"
    t1 = timer()
    #print "\nCommit message rate: %2.2f / sec" % (1.0 / ((t1-t0)/(len(responses))))
    
    
    ## log verification test
    t0 = timer()
    logger = RSCLogger()
    last_queried_tx, data, core = mesages_q[-1]
    authPub = factory.key.pub.export(EcPt.POINT_CONVERSION_UNCOMPRESSED)
    seq =  len(mesages_q)
    
    quired_hashhead, sig, dataCore = logger.query_hashhead(last_queried_tx.id(), authPub, 
                                            seq)
    assert quired_hashhead !=None
    
    new_h = sha256(" ".join( dataCore
                            + [quired_hashhead] 
                            +[str(seq)])).digest()
    
    assert factory.key.verify(new_h, sig)
    
    assert logger.verify_log(len(mesages_q), quired_hashhead) == True
    assert logger.verify_log(int(seqStr), hashhead) == True
    t1 = timer()
    
    ## test hashhead query protocol
    data = package_hashQuery(last_queried_tx, authPub, str(seq))
    tr.clear()
    instance.lineReceived(data)
    response = tr.value()
    quired_hashhead, sig, dataCore = unpackage_hash_response(response)
    assert quired_hashhead !=None
    
    new_h = sha256(" ".join( dataCore
                            + [quired_hashhead] 
                            +[str(seq)])).digest()
    
    assert factory.key.verify(new_h, sig)
    
    auditor = Auditor(factory.directory, factory.special_key)
    
    t0 = timer() 
    assert auditor.audit_log(factory.key.id(), "localhost", 27017, factory.get_hash_head(), 2000)
    t1 = timer()
    
    # the seq == the number of entries because there is only one mintette
    print "\nLog auditing rate: %2.2f / sec" % (1.0 / ((t1-t0)/(seq)))
    
    
    