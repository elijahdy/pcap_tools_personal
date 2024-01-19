import unittest
import os
import sys
#run from cwd=pcap_tools_personal
sys.path.append(os.getcwd())
from scapy.all import *
from pcap_analysis import *

class AnalysisTest(unittest.TestCase):
    #must run generation test and obtain pcap outputs first in order to run this test.
    def __init__(self, methodName: str = "testAnalysis") -> None:
        super().__init__(methodName)

    def create_logging_file(self):
        log_directory = os.path.dirname(__file__)+"/test_files/"
        log_file_path = os.path.join(log_directory, "AnalysisTest.log")
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
    
    def getFileNames(self,folder_path):
        try:
            files = os.listdir(folder_path)
            file_names = [file for file in files if os.path.isfile(os.path.join(folder_path, file))]
            return file_names
        except Exception as e:
            print(f"An error occurred: {e}")
            return None

    def setUp(self) -> None:
        self.create_logging_file()
        self.dr = os.path.dirname(__file__)+"/../pcap_generation_tests/"
        self.byteCntByteRateFiles = self.getFileNames(self.dr+"ByteCountBasedByteRateStream_test_results")
        self.pktCntPktRateFiles = self.getFileNames(self.dr+"PktCountBasedPktRateStream_test_results")
        self.pktCntIPGFiles = self.getFileNames(self.dr+"PktCountBasedIPGStream_test_results")
        self.timeIPGFiles = self.getFileNames(self.dr+"TimeBasedIPGStream_test_results")
        self.timePktRateFiles = self.getFileNames(self.dr+"TimeBasedPktRateStream_test_results")
        self.timeByteRateFiles = self.getFileNames(self.dr+"TimeBasedByteRateStream_test_results")
        return super().setUp()
    
    def getSubstringBetween(self, original_string: string, start_substring: string, end_substring: string):
        start_index = original_string.find(start_substring)
        end_index = original_string.find(end_substring)
        if start_index != -1 and end_index != -1:
            start_index += len(start_substring)
            return original_string[start_index:end_index]
        else:
            return None

    def parseAssertionValues(self, drNum, filename):
        if drNum == 1:
            br = float(self.getSubstringBetween(filename,"byteRate:","_byteCount"))
            bc = int(self.getSubstringBetween(filename,"byteCount:","_fwp"))
            fwp = self.getSubstringBetween(filename,"fwp:",".pcap")
            return (br,bc,fwp)
        if drNum == 2:
            aveIPG = float(self.getSubstringBetween(filename,"aveIPG:","_IPGRange"))
            pc = int(self.getSubstringBetween(filename,"_numPackets:",".pcap"))
            return (aveIPG,pc)
        if drNum == 3:
            pr = float(self.getSubstringBetween(filename,"packetRate:","_packetCount"))
            pc = int(self.getSubstringBetween(filename,"_packetCount:",".pcap"))
            return (pr, pc)
        if drNum == 4:
            br = float(self.getSubstringBetween(filename,"byteRate:","_time"))
            time = float(self.getSubstringBetween(filename,"_time:",".pcap"))
            return (br, time)
        if drNum == 5:
            aveIPG = float(self.getSubstringBetween(filename,"aveIPG:","_IPGRange"))
            time = float(self.getSubstringBetween(filename,"_time:",".pcap"))
            return (aveIPG, time)
        if drNum == 6:
            pr = float(self.getSubstringBetween(filename,"packetRate:","_time"))
            time = float(self.getSubstringBetween(filename,"_time:",".pcap"))
            return (pr, time)
        
    def testAnalysis(self):
        testcase = 1
        for filename in self.byteCntByteRateFiles:
            logging.info(f"-------------|Test-Case {testcase}: using input file {filename}|----------------")
            assertionValues = self.parseAssertionValues(1, filename)
            anal = TrafficAnalyser.fromPcap(self.dr+"ByteCountBasedByteRateStream_test_results/"+filename)
            if assertionValues[2] == 'False' and anal.totalPackets > 1:
                try:
                    self.assertAlmostEqual(anal.byteRate,assertionValues[0],3)
                    logging.info("Correct byte rate")
                except AssertionError as e:
                    logging.error(f"Calculated byte rate does not match configured byte rate: {e}")
            else:
                try:
                    self.assertAlmostEqual(anal.totalBytes,assertionValues[1])
                    logging.info("Correct byte count")
                except AssertionError as e:
                    logging.error(f"Calculated byte count does not match configured byte count {e}")
            testcase += 1
        for filename in self.pktCntIPGFiles:
            logging.info(f"-------------|Test-Case {testcase}: using input file {filename}|----------------")
            assertionValues = self.parseAssertionValues(2, filename)
            anal = TrafficAnalyser.fromPcap(self.dr+"PktCountBasedIPGStream_test_results/"+filename)
            try:
                self.assertEqual(anal.totalPackets,assertionValues[1])
                logging.info("Correct packet count")
            except AssertionError as e:
                    logging.error(f"Calculated packet count does not match configured packet count: {e}")
            if anal.totalPackets > 1:
                try:
                    self.assertAlmostEqual(anal.meanIpg,assertionValues[0],3)
                    logging.info("Correct mean IPG")
                except AssertionError as e:
                    logging.error(f"Calculated mean IPG does not match configured mean IPG: {e}")
            testcase += 1
        for filename in self.pktCntPktRateFiles:
            assertionValues = self.parseAssertionValues(3, filename)
            anal = TrafficAnalyser.fromPcap(self.dr+"PktCountBasedPktRateStream_test_results/"+filename)
            logging.info(f"-------------|Test-Case {testcase}: using input file {filename}|----------------")
            try:
                self.assertEqual(anal.totalPackets,assertionValues[1])
                logging.info("Correct packet count")
            except AssertionError as e:
                    logging.error(f"Calculated packet count does not match configured packet count: {e}")
            if anal.totalPackets > 1:
                try:
                    self.assertAlmostEqual(anal.packetRate,assertionValues[0],3)
                    logging.info("Correct packet rate")
                except AssertionError as e:
                    logging.error(f"Calculated packet rate does not match configured packet rate: {e}")
            testcase += 1
        for filename in self.timeByteRateFiles:
            assertionValues = self.parseAssertionValues(4, filename)
            anal = TrafficAnalyser.fromPcap(self.dr+"TimeBasedByteRateStream_test_results/"+filename)
            logging.info(f"-------------|Test-Case {testcase}: using input file {filename}|----------------")
            if anal.totalPackets > 1:
                try:
                    self.assertAlmostEqual(anal.byteRate,assertionValues[0],3)
                    logging.info("Correct byte rate")
                except AssertionError as e:
                    logging.error(f"Calculated byte rate does not match configured byte rate: {e}")
                try:
                    self.assertAlmostEqual(anal.totalTime,assertionValues[1],3)
                    logging.info("Correct total time")
                except AssertionError as e:
                    logging.error(f"Calculated total time does not match configured total time {e}")
                testcase += 1
        for filename in self.timeIPGFiles:
            assertionValues = self.parseAssertionValues(5, filename)
            anal = TrafficAnalyser.fromPcap(self.dr+"TimeBasedIPGStream_test_results/"+filename)
            logging.info(f"-------------|Test-Case {testcase}: using input file {filename}|----------------")
            if anal.totalPackets > 1:
                try:
                    self.assertAlmostEqual(anal.meanIpg,assertionValues[0],3)
                    logging.info("Correct mean IPG")
                except AssertionError as e:
                    logging.error(f"Calculated mean IPG does not match configured mean IPG {e}")
                try:
                    self.assertAlmostEqual(anal.totalTime,assertionValues[1],3)
                    logging.info("Correct total time")
                except AssertionError as e:
                    logging.error(f"Calculated total time does not match configured total time {e}")
                testcase += 1
        for filename in self.timePktRateFiles:
            assertionValues = self.parseAssertionValues(6, filename)
            anal = TrafficAnalyser.fromPcap(self.dr+"TimeBasedPktRateStream_test_results/"+filename)
            logging.info(f"-------------|Test-Case {testcase}: using input file {filename}|----------------")
            if anal.totalPackets > 1:
                try:
                    self.assertAlmostEqual(anal.packetRate,assertionValues[0],5)
                    logging.info("Correct packet rate")
                except AssertionError as e:
                    logging.error(f"Calculated packet rate does not match configured packet rate {e}")
                try:
                    self.assertAlmostEqual(anal.totalTime,assertionValues[1],5)
                    logging.info("Correct total time")
                except AssertionError as e:
                    logging.error(f"Calculated total time does not match configured total time {e}")
                testcase += 1

if __name__ == "__main__":
    t = AnalysisTest()
    t.setUp()
    t.testAnalysis()
