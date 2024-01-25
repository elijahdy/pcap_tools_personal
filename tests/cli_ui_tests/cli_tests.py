import subprocess
import unittest
import platform
import logging
import os
import sys
#run from cwd=pcap_tools_personal
sys.path.append(os.getcwd())

class CliTests(unittest.TestCase):
    def __init__(self, methodName: str = "testCli") -> None:
        super().__init__(methodName)
    
    def create_logging_file(self):
        log_directory = os.path.dirname(__file__)+"/test_files/"
        log_file_path = os.path.join(log_directory, "cliTest.log")
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
    
    def setUp(self) -> None:
        self.create_logging_file()
        logging.info('Setting up genpcap cli tool ...')
        try:
            subprocess.run('pip install -e .', shell=True, check=True)
        except subprocess.CalledProcessError as e:
            logging.error(f'failed to set up tool {e}')
            exit()
        if platform.system() == "Windows":
            self.call = 'python genpcap.py '
        else:
            self.call = 'genpcap.py '
        self.fnPrefix = f'-fn {os.path.dirname(__file__)}/test_files/'
        self.defaultCase = '-pt ipv4 -up 0x0000000000000000 -pkc 10 -pr 60'
        self.errorCases = ['-pt ipv4 -up 0x0000000000000000 -pr 60 -pkc 10 -tst 123',
                      '-pt ipv4 -up 0x0000000000000000 -pkc 10 -pr 40 -br 80',
                      '-pt ipv4 -up 0x0000000000000000 -rfl true -rsz true -pkc 10 -pr 60',
                      '-pt vlan -vtt double -pcp 1 -vid 1 -up 0x0000000000000000 -pkc 10 -pr 60',
                      '-hd wawavingwawaba -up 0x0000000000000000 -pkc 10 -pr 60',
                      '-hd ethernet -vtt single -up 0x0000000000000000 -pkc 10 -pr 60',
                      '-hd ethernet -mplbl 1 -up 0x0000000000000000 -pkc 10 -pr 60',
                      '-hd ethernet -v4src 111.12.18.3 -up 0x0000000000000000 -pkc 10 -pr 60',
                      '-hd ethernet -v6src 0000:1111:2222:3333:4444:5555:6666:7777 -up 0x0000000000000000 -pkc 10 -pr 60',
                      '-hd ethernet -gv 1 -up 0x0000000000000000 -pkc 10 -pr 60',
                      '-hd ethernet -tsrc 1 -up 0x0000000000000000 -pkc 10 -pr 60',
                      '-hd ethernet -usrc 1 -up 0x0000000000000000 -pkc 10 -pr 60',
                      '-hd ethernet -erv 1 -up 0x0000000000000000 -pkc 10 -pr 60',
                      '-hd ethernet -rst 1 -up 0x0000000000000000 -pkc 10 -pr 60',
                      '-pt wawavingwawaba -up 0x0000000000000000 -pkc 10 -pr 60',
                      '-pt ipv4 -pcp 1 -up 0x0000000000000000 -pkc 10 -pr 60',
                      '-pt ipv4 -mpqos 1 -up 0x0000000000000000 -pkc 10 -pr 60',
                      '-pt ethernet -v4prot 1 -up 0x0000000000000000 -pkc 10 -pr 60',
                      '-pt ipv4 -v6prot 1 -up 0x0000000000000000 -pkc 10 -pr 60',
                      '-pt ipv4 -gmt 1 -up 0x0000000000000000 -pkc 10 -pr 60',
                      '-pt ipv4 -tdst 1 -up 0x0000000000000000 -pkc 10 -pr 60',
                      '-pt ipv4 -udst 1 -up 0x0000000000000000 -pkc 10 -pr 60',
                      '-pt ipv4 -ec 1 -up 0x0000000000000000 -pkc 10 -pr 60',
                      '-pt ipv4 -rid 1 -up 0x0000000000000000 -pkc 10 -pr 60',]
        self.normalCases = ['-hd ethernet -up 0x0000000000000000 -pkc 10 -pr 60',
                            '-pt vlan -vtt single -up 0x0000000000000000 -pkc 10 -pr 60',
                            '-hd ethernet vlan -vtt double -up 0x0000000000000000 -pkc 10 -pr 60',
                            '-pt mpls -up 0x0000000000000000 -pkc 10 -pr 60',
                            '-hd ethernet ipv6 -up 0x0000000000000000 -pkc 10 -pr 60',
                            '-pt gtp -up 0x0000000000000000 -pkc 10 -pr 60',
                            '-hd ethernet ipv4 tcp -up 0x0000000000000000 -pkc 10 -pr 60',
                            '-pt udp -up 0x0000000000000000 -pkc 10 -pr 60',
                            '-hd ethernet ecpri -up 0x0000000000000000 -pkc 10 -pr 60',
                            '-pt roe -up 0x0000000000000000 -pkc 10 -pr 60',
                            '-hd ethernet ipv4 udp gtp -gv 1 -up 0x0000000000000000 -pkc 10 -pr 60',
                            '-pt gtp -gv 2 -up 0x0000000000000000 -pkc 10 -pr 60',
                            '-pt ipv4 -np -pkc 10 -pr 60',
                            '-pt ipv4 -ifl 33 -isz 8 -flstp -3 -szstp 8 -mnsz 8 -mxsz 128  -szstp 8 -pkc 10 -pr 60',
                            '-pt ipv4 -up 0x0000000000000000 -pkc 10 -aipg 18 -ipgr 6',
                            '-pt ipv4 -up 0x0000000000000000 -tst 40 -aipg 3 -ipgr 0.5',
                            '-pt ipv4 -up 0x0000000000000000 -tst 55 -pr 60',
                            '-pt ipv4 -up 0x0000000000000000 -bc 300 -br 75',
                            '-pt ipv4 -up 0x0000000000000000 -tst 67 -br 77',]
        return super().setUp()
    
    def checkErroneousCommand(self, commandArgs: str, caseNo: int):
        logging.info(f"Running Test-Case {caseNo}")
        try:
            completedProcess = subprocess.run(f'{self.call}{self.fnPrefix}tc{caseNo} {commandArgs}', shell=True, check=True)
            logging.error(f"Invalid cli command did not raise error as expected command returned {completedProcess}")
        except subprocess.CalledProcessError as e:
            logging.info(f"Exception raised as expected:{e} test-case passed")
            logging.info("Test-case passed")
            
    
    def runCommand(self, commandArgs: str, caseNo: int):
        logging.info(f"Running Test-Case {caseNo}")
        try:
            completedProcess = subprocess.run(f'{self.call}{self.fnPrefix}tc{caseNo} {commandArgs}', shell=True, check=True)
            logging.info(f"Successfully executed test-case process call{completedProcess}")
            logging.info(f"pcap saved in test_files as tc{caseNo}.pcap")
        except subprocess.CalledProcessError as e:
            logging.error(f"There was a problem executing the test-case command:{e}")
    
    def testCli(self):
        self.runCommand(self.defaultCase, 1)
        caseNo = 2
        for caseArgs in self.errorCases:
            self.checkErroneousCommand(caseArgs, caseNo)
            caseNo += 1
        for caseArgs in self.normalCases:
            self.runCommand(caseArgs,caseNo)
            caseNo += 1
         
           
if __name__ == "__main__":
    unittest.main()