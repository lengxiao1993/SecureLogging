#!/usr/bin/python


import rscoin
from rscoin.rscservice import RSCFactory, load_setup, get_authorities,\
    unpackage_hash_response, package_hashQuery
from tests.test_rscservice import sometx, msg_mass
from rscoin.logging import RSCLogEntry, RSCLogger, decode_json_to_log_entry, \
                           encode_log_entry_to_json, Auditor
import thread
import argparse
import socket

def main():
    dir_data = load_setup(file("directory.conf").read())
    directory = [(kid, socket.gethostbyname(ip), port) for (kid, ip, port) in dir_data["directory"] ]
    special_id = dir_data["special"]
    
    parser = argparse.ArgumentParser(description='RSCoin auditor client.')
    
    parser.add_argument('--online_audit', action='store_true', help='randomly audit the mintettes behavior during current epoch')
    parser.add_argument('--local_test', action='store_true', help='test auditing function locally')
    parser.add_argument('--remote_test', action='store_true', help='')
    args = parser.parse_args()
    
    if args.online_audit:
        # Create two threads as follows
        threadNum = 30
        for _ in range(threadNum):
            auditor = Auditor(directory, special_id)
            
            try:
                thread.start_new_thread( auditor.start_online_audit,())
            except Exception, e:
                print "Error: unable to start thread %s" % e
            
            while 1:
                pass        
        
    
    if args.local_test:
        secret = "A" * 32
        public = rscoin.Key(secret, public=False).id()
        directory = [(public, "127.0.0.1", 8080)]
        auditor = Auditor(directory, special_id)
        assert auditor.start_online_audit()
        
    if args.remote_test:
        for (kid, ip, port) in directory:
            logger = RSCLogger(ip,27017)
            print logger.query_total_number()
            
main()

    
    
        
        