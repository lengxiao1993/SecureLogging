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
from rscoin.logging import RSCLogger, RSCLogEntry

def load_setup(setup_data):
    structure = loads(setup_data)
    structure["special"] = b64decode(structure["special"])
    structure["directory"] = [(b64decode(a), b, c) for a,b,c in structure["directory"]]   
    #??? b64decode(a) is 29 bytes ????
    """"{
	"special": "AmodBjXyo2bVqyi1h0e5Kf8hSbGCmalnbF8YwJ0=",
    "directory": [ ["A/Sw7CRkoXzB2O0A3WfPMSDIbv/pOxd5Co3u9kM=", "127.0.0.1", 8080] ] 
    }"""

    return structure


def package_query(tx, tx_deps, keys):  
    #??? "tx_deps" are input transactions for tx
    #??? "keys" are public keys of addr that received value in "tx_deps"
    items = [ tx.serialize() ]
    for txi in tx_deps:
        items += [ txi.serialize() ]

    for k in keys:
        items += [ k.export()[0] ]       #export the key into string 

    for k in keys:
        items += [ k.sign(tx.id()) ]

    dataCore = map(b64encode, items)    
    
    H = sha256(" ".join(dataCore)).digest()
    data = " ".join(["xQuery", str(len(dataCore))] + dataCore)

    return H, data, dataCore


def unpackage_query_response(response):
    resp = response.strip().split(" ")
    
    code = resp[0]
    if code == "OK" or code == "Pong":
        resp[1:] = map(b64decode, resp[1:])

    return resp


def package_commit(core, kshs_list):
    """ Kshs_list is the list of auth_keys and auth_signatures 
        hashheads, sequence numbers
    """
    
    kshs_flat = []
    for (key, signature, hashhead, seqStr) in kshs_list:
        kshs_flat += [ key, signature, hashhead, seqStr ]

    data = " ".join(["xCommit", str(len(core))] + core +
                     map(b64encode, kshs_flat))
    return data


def package_issue(tx, ks):
    tx_ser = tx.serialize()
    k, s = ks
    core = map(b64encode, [tx_ser, k.export()[0], s])
    data = " ".join(["xCommit", str(len(core))] + core)
    return data, core


def unpackage_commit_response(response):
    resp = response.strip().split(" ")
    
    code = resp[0]
    if code == "OK" or code == "Pong":
        resp[1:] = map(b64decode, resp[1:])

    return resp


class RSCProtocol(LineReceiver):

    def __init__(self, factory):
        self.factory = factory

    @staticmethod
    def parse_Tx_bundle(bundle_items, items):
        """ Common parsing code for the Tx bundle """

        assert len(items) == bundle_items
        H = sha256(" ".join(items)).digest()

        items = map(b64decode, items)
        mainTx = rscoin.Tx.parse(items.pop(0))

        otherTx, keys, sigs = [], [], []
        if len(mainTx.inTx) > 0:
                    size = len(mainTx.inTx)
                    for _ in range(size):
                        otherTx += [items.pop(0)]
                    for _ in range(size):
                        keys += [items.pop(0)]
                    for _ in range(size):
                        sigs += [items.pop(0)]
        elif len(mainTx.inTx) == 0:
                    keys += [items.pop(0)]
                    sigs += [items.pop(0)]

        assert len(items) == 0
        
        return H, (mainTx, otherTx, keys, sigs)


    def handle_Query(self, items):
        """ Process the query message and respond """
        bundle_size = int(items[1])

        try:
            items = items[2:2+bundle_size]
            H, data = RSCProtocol.parse_Tx_bundle( bundle_size, items)
            (mainTx, otherTx, keys, sigs) = data

            # Specific checks
            assert len(otherTx) > 0
            assert len(items[2+bundle_size:]) == 0

            # TODO: checkhere this Tx falls within our remit         #???? to be added

        except Exception as e:
            print_exc()
            self.return_Err("ParsingError")
            return 

        try:            
            # Check the Tx Query
            res = self.factory.process_TxQuery(data)
        except Exception as e:
            print_exc()
            self.return_Err("QueryError")
            return 

        # If Query failed
        if not res:
            self.sendLine("NOTOK" )
            return
        
        #... when all the checks passed, create log entry
        
        seq = self.factory.get_lamp_clock()
        
        logEntry = RSCLogEntry(data, "Query_Success", lampClock = seq)
        
        newHashHead = sha256(logEntry.serialize()
                             +
                             self.factory.get_hash_head()
                             ).digest()
        
        self.factory.update_hash_head(newHashHead)
        
        self.factory.logger.write_log(logEntry)
        
        H = sha256(" ".join(items
                            + [newHashHead] 
                            +[str(seq)])).digest()
         
        
        self.sendLine("OK %s %s %s" % (
                                       self.sign(H),
                                       b64encode(newHashHead),
                                       b64encode(str(seq))
                                       )
                      )
        
        return

    def handle_Commit(self, items):
        """ Process the commit message and respond """
        
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
            self.return_Err("ParsingError")
            return

        data = (H, mainTx, otherTx, keys, sigs, 
                auth_keys, auth_sigs, hashheads, seqStrs, items)
        res = self.factory.process_TxCommit(data)

        if not res:
            self.sendLine("NOTOK")
            return
        
        
        if len(seqStrs) == 0:
            # The issue transaction without seqencenumber
            seq = self.factory.get_lamp_clock()
        
        else: 
            seqInts = map(int, seqStrs)        
            seqMax = max(seqInts)
            seq = self.factory.get_lamp_clock(seqMax)
        
        logEntry = RSCLogEntry(data, "Commit_Success", lampClock = seq)
        
        newHashHead = sha256(logEntry.serialize()
                             +
                             self.factory.get_hash_head()
                             ).digest()
        
        self.factory.update_hash_head(newHashHead)
        
        self.factory.logger.write_log(logEntry)
        
        new_h = sha256(" ".join(items
                            + [newHashHead] 
                            +[str(seq)])).digest()
            
        #h = mainTx.id()
        ret = self.sign(new_h)
        
        self.sendLine("OK %s %s %s" % (ret, b64encode(newHashHead), 
                                       b64encode(str(seq)) 
                                       )
                                       )
        

    def lineReceived(self, line):
        """ Simple de-multiplexer """

        items = line.split(" ")
        if items[0] == "xQuery":
            return self.handle_Query(items) # Get signatures           

        if items[0] == "xCommit":
            return self.handle_Commit(items) # Seal a transaction

        if items[0] == "Ping":
            self.sendLine("Pong %s" % b64encode(self.factory.key.id()))
            return # self.handle_Commit(items) # Seal a transaction

        self.return_Err("UnknownCommand:%s" % items[0])
        return

    def sign(self, H):
        """ Generic signature """
        k = self.factory.key
        pub = k.pub.export(EcPt.POINT_CONVERSION_UNCOMPRESSED)
        
        sig = k.sign(H)
        return " ".join(map(b64encode, [pub, sig]))


    def return_Err(self, Err):
        self.sendLine("Error %s" % Err)


class RSCFactory(protocol.Factory):

    _sync = True

    def __init__(self, secret, directory, special_key, conf_dir=None, N=3):
        """ Initialize the RSCoin server"""
        self.special_key = special_key
        self.key = rscoin.Key(secret, public=False)
        self.directory = sorted(directory)
        keyID = self.key.id()[:10]
        self.N = N

        # Open the databases
        self.dbname = 'keys-%s' % hexlify(keyID)
        self.logname = 'log-%s' % hexlify(keyID)
        
        self.logger = RSCLogger()
        
        
        
        if conf_dir:
            self.dbname = join(conf_dir, self.dbname)
            self.logname = join(conf_dir, self.logname)

        if RSCFactory._sync:                                
            self.db = dbm.open(self.dbname, 'c')
            self.log = dbm.open(self.logname, 'c')
            
            ###????? RSCFactory._sync is set for synchronous writing to the disk          
            ### c mode means for both writing and reading, if the file does not exist, it will be created
        else:
            self.db = {} 
            self.log = {}
            self.log["hashhead"] = ""
            self.log["lampClock"] = 0
    
    def buildProtocol(self, addr):
        cli = RSCProtocol(self)
        return cli


    def process_TxQuery(self, data):
        """ Queries a full transaction and gets a signed response if it is valid. 

            When I get a query:
            * Check that the signatures check.
            * Check the input addresses are in the utxo.
            * Check that they are not used, or used for same.
            * Add to spent transactions.
            * Remove from utxo.

        """

        mainTx, otherTx, keys, sigs = data
        mid = mainTx.id()
        inTxo = mainTx.get_utxo_in_keys()

        # Check that at least one Input is handled by this server
        should_handle_ik = []
        for ik in inTxo:
            lst = self.get_authorities(ik)
            if self.key.id() in lst:
                should_handle_ik += [ ik ]

        if should_handle_ik == []:
            #print("Not in ID range.")
            return False

        # Check the transaction is well formed
        #... well formed means every input transaction has valid signatures from corresponding mintettes who certify the transactions have not been spent
        
        all_good = mainTx.check_transaction(otherTx, keys, sigs)
        if not all_good:
            print("Failed TX check")
            return False

        ## Check all inputs are in
        for ik in should_handle_ik:
            ## We are OK if this is already in the log with the same mid
            if ik in self.log and self.log[ik] == mid:              #??? self.log is the "pset" list in the paper
                continue
            ## Otherwise it should not have been used yet
            elif ik not in self.db:                                 #??? self.db is the "utxo" list in the paper
                print b64encode(ik)[:8]
                print("Failed utxo check")
                return False

        # Once we know all is good we proceed to remove them
        # but write the decision to a log
        for ik in should_handle_ik:
            if ik in self.db:
                del self.db[ik]
            self.log[ik] = mid          
            #... self.db is the "utxo" list in the paper 
            #... self.log is the "pset" list in the paper
            
        # Save before signing
        if RSCFactory._sync:
            self.db.sync()              #???
            self.log.sync()       
        return True

    def process_TxCommit(self, data):
        """ Provides a Tx and a list of responses, and commits the transaction. """
        H, mainTx, otherTx, keys, sigs, auth_pub, auth_sig, hashheads, seqStrs, items \
        = data

        # Check that this Tx is handled by this server
        ik = mainTx.id()
        lst = self.get_authorities(ik)
        should_handle = (self.key.id() in lst)

        if not should_handle:
            log.msg('Failed Tx ID range ownership')
            return False
        
        # First check all signatures
        all_good = True
        pub_set = []
        
        # hh is hea
        for pub, sig, hh, s in zip(auth_pub, auth_sig, hashheads, seqStrs):
            key = rscoin.Key(pub)
            pub_set += [ key.id() ]
            
            new_H = sha256(" ".join(  items
                            + [hh] 
                            + [s])
                   ).digest()
            
            all_good &= key.verify(new_H, sig)

        if not all_good:
            log.msg('Failed Tx Signatures')
            return False

        # Check the transaction is well formed
        all_good = mainTx.check_transaction(otherTx, keys, sigs, masterkey=self.special_key)
        if not all_good:
            log.msg('Failed Tx Validity')
            return False

        pub_set = set(pub_set)

        # Now check all authorities are involved
        mid = mainTx.id()
        inTxo = mainTx.get_utxo_in_keys()
        for itx in inTxo:
            ## Ensure we have a Quorum for each input
            aut = set(self.get_authorities(itx))
            all_good &= (len(aut & pub_set) > len(aut) / 2) 

        if not all_good:
            log.msg('Failed Tx Authority Consensus')
            return False

        # Now check we have not already spent the transaction
        all_good &= (mid not in self.log)

        if not all_good:
            log.msg('Failed Tx Doublespending')
            return False

        ## TODO: Log all information about the transaction

        # Update the outTx entries
        for k, v in mainTx.get_utxo_out_entries():
            self.db[k] = v
        
        if RSCFactory._sync:
            self.db.sync()

        return all_good


    def get_authorities(self, xID):
        """ Returns the keys of the authorities for a certain xID """
        return get_authorities(self.directory, xID, self.N)
    
    def update_hash_head(self, currentHashHead):
        """ update the hash head of  the RSCFactory's logging entries"""
        #... notice this log is not logging database
        #... self.log is used to maintain pset and hashhead of logging database
        self.log["hashhead"] = currentHashHead
    
    def get_hash_head(self):
        """ fetch the hash head of the RSCFactory's logging entries """
        
        return self.log["hashhead"]
    
    def get_lamp_clock(self, receivedClcok = None):
        
        localClock = self.log["lampClock"]
        if(receivedClcok == None or receivedClcok < receivedClcok):
            self.log["lampClock"] = localClock + 1
            return self.log["lampClock"]
        else:
            self.log["lampClock"] = receivedClcok + 1
            return self.log["lampClock"]
    
    


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
