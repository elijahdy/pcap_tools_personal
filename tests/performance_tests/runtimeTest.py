import unittest
import time
import os
import sys
#run from cwd=pcap_tools_personal
sys.path.append(os.getcwd())
from scapy.all import *
from pcap_analysis import *
from pcap_generation import *

class RunTimeTest(unittest.TestCase):
    def __init__(self, methodName: str = "testRunTime") -> None:
        super().__init__(methodName)
    
    def create_logging_file(self):
        log_directory = os.path.dirname(__file__)+"/test_files/"
        log_file_path = os.path.join(log_directory, "performanceTest.log")
        if not os.path.exists(log_directory):
            os.makedirs(log_directory)  
        if os.path.exists(log_file_path):
            logging.shutdown()
            os.remove(log_file_path)
        logging.basicConfig(
            filename=log_file_path,
            level=logging.INFO,
            format='%(asctime)s [%(levelname)s] - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        logging.info(f"Log file created at {log_file_path}")
    
    def testRunTime(self):
        self.create_logging_file()
        logging.info("Executing pcap generation and analysis runtime test")
        startTime = time.time()
        Session([PktCountBasedIPGStream(HeaderFrame.fromHeaderList([EthernetHeader(),VLANHeaderDouble(),MPLSHeader(),Ipv6Header(),TCPHeader(),GTPv2Header()]),
                                        PredefinedPayloadGenerator(initialSize=1024,minSize=1024,maxSize=1024),
                                        10000, 0, 10000)], False
                ).sink(os.path.dirname(__file__)+"/test_files/performanceTestLargePcap")
        midpoint = time.time()
        generationTime = midpoint - startTime
        logging.info(f"pcap generated in {generationTime}(s)")
        anal = TrafficAnalyser.fromPcap(os.path.dirname(__file__)+"/test_files/performanceTestLargePcap.pcap")
        anal.summary()
        endTime = time.time()
        analysisTime = endTime-midpoint
        logging.info(f"pcap analysed in {analysisTime}(s)")
        totalTime = endTime - startTime
        if totalTime <= 60:
            logging.info(f"Test Passed runtime:{totalTime}(s)")
        else:
            logging.error(f"Test Failed runtime:{totalTime}(s)")
        

RunTimeTest().testRunTime()