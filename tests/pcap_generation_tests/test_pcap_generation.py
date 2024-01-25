import unittest
import os
import sys
#run from cwd=pcap_tools_personal
sys.path.append(os.getcwd())
from scapy.all import *
from pcap_generation import *

class PktCountBasedIPGStreamTest(unittest.TestCase):

    def __init__(self, methodName: str = "testPktCntIPG") -> None:
        super().__init__(methodName)

    def genInputs(self) -> list[tuple[HeaderFrame, PayloadGenerator, float, float, int]]:
        headerFrames = [HeaderFrame.fromHeaderList([EthernetHeader(),Ipv4Header(),TCPHeader()]),HeaderFrame.fromHeaderList([EthernetHeader(),RoEHeader()]),HeaderFrame.fromHeaderList([EthernetHeader(),VLANHeaderSingle(),Ipv6Header(),UDPHeader()])]
        payloadGens = [PredefinedPayloadGenerator(randomFills=True, sizeStep=2),UserPayloadGenerator(["0x48656C6C6F576F726C64","0x4D794E616D65734973456C696A61684E69676761"])]
        numPackets = [1, 30, 1000, 1000]
        aveIPGs = [1.3, 15.5, 999999.01]

        inputs = []

        for header in headerFrames:
            for payload in payloadGens:
                for num in numPackets:
                    for ipg in aveIPGs:
                        input1 = (header, payload, ipg, 0, num)
                        input2 = (header, payload, ipg, ipg/4, num)
                        input3 = (header, payload, ipg, ipg/2, num)
                        inputs.append(input1)
                        inputs.append(input2)
                        inputs.append(input3)
        return inputs
    
    def erroneousTests(self):
        default = (HeaderFrame.fromHeaderList([EthernetHeader(),Ipv4Header(),TCPHeader()]), PredefinedPayloadGenerator(randomFills=True, sizeStep=2), 10, 4, 100)
        PktCountBasedIPGStream(default[0],default[1],default[2],default[3],default[4])
        try:
            PktCountBasedIPGStream(default[0],default[1],-10,default[3],default[4])
            raise AssertionError
        except (BaseException):
            pass
        try:
            PktCountBasedIPGStream(default[0],default[1],0,default[3],default[4])
            raise AssertionError
        except (BaseException):
            pass
        try:
            PktCountBasedIPGStream(default[0],default[1],default[2],-6.66,default[4])
            raise AssertionError
        except (BaseException):
            pass
        try:
            PktCountBasedIPGStream(default[0],default[1],default[2],5.001,default[4])
            raise AssertionError
        except (BaseException):
            pass
        try:
            PktCountBasedIPGStream(default[0],default[1],default[2],default[3],-42)
            raise AssertionError
        except (BaseException):
            pass
        try:
            PktCountBasedIPGStream(default[0],default[1],default[2],default[3],0)
            raise AssertionError
        except (BaseException):
            pass
        try:
            PktCountBasedIPGStream(default[0],default[1],default[2],default[3],8.4)
            raise AssertionError
        except (BaseException):
            pass
    
    def validTests(self,inputs):
        for input in inputs:
            stream = PktCountBasedIPGStream(input[0],input[1],input[2],input[3],input[4])
            session = Session([stream],False)
            session.sink(os.path.dirname(__file__)+f"/PktCountBasedIPGStream_test_results/HF:{input[0]}_PG:{input[1]}_aveIPG:{input[2]}_IPGRange:{input[3]}_numPackets:{input[4]}")
    
    def testPktCntIPG(self):
        self.erroneousTests()
        inputs = self.genInputs()
        self.validTests(inputs)


class TimeIPGStreamTest(unittest.TestCase):

    def __init__(self, methodName: str = "testTimeIPG") -> None:
        super().__init__(methodName)
    
    def genInputs(self) -> list[tuple[HeaderFrame, PayloadGenerator, float, float]]:
        headerFrames = [HeaderFrame.fromHeaderList([EthernetHeader(),Ipv4Header(),TCPHeader()]),HeaderFrame.fromHeaderList([EthernetHeader(),RoEHeader()]),HeaderFrame.fromHeaderList([EthernetHeader(),VLANHeaderSingle(),Ipv6Header(),UDPHeader()])]
        payloadGens = [PredefinedPayloadGenerator(randomFills=True, sizeStep=2),UserPayloadGenerator(["0x48656C6C6F576F726C64","0x4D794E616D65734973456C696A61684E69676761"])]
        times = [2.1, 34.77, 103.17, 1369.3]
        aveIPGs = [1.4, 213.44, 921.82]

        inputs = []

        for header in headerFrames:
            for payload in payloadGens:
                for time in times:
                    for ipg in aveIPGs:
                        input1 = (header, payload, ipg, 0, time)
                        input2 = (header, payload, ipg, ipg/4, time)
                        input3 = (header, payload, ipg, ipg/2, time)
                        inputs.append(input1)
                        inputs.append(input2)
                        inputs.append(input3)
        return inputs
    
    def erroneousTests(self):
        default = (HeaderFrame.fromHeaderList([EthernetHeader(),Ipv4Header(),TCPHeader()]), PredefinedPayloadGenerator(randomFills=True, sizeStep=2), 50, 21, 100)
        PktCountBasedIPGStream(default[0],default[1],default[2],default[3],default[4])
        try:
            TimeBasedIPGStream(default[0],default[1],-9999999999,default[3],default[4])
            raise AssertionError
        except (BaseException):
            pass
        try:
            TimeBasedIPGStream(default[0],default[1],0,default[3],default[4])
            raise AssertionError
        except (BaseException):
            pass
        try:
            TimeBasedIPGStream(default[0],default[1],default[2],-422,default[4])
            raise AssertionError
        except (BaseException):
            pass
        try:
            TimeBasedIPGStream(default[0],default[1],default[2],25.00001,default[4])
            raise AssertionError
        except (BaseException):
            pass
        try:
            TimeBasedIPGStream(default[0],default[1],default[2],default[3],-11)
            raise AssertionError
        except (BaseException):
            pass
        try:
            TimeBasedIPGStream(default[0],default[1],default[2],default[3],0)
            raise AssertionError
        except (BaseException):
            pass
    
    def validTests(self,inputs):
        for input in inputs:
            stream = TimeBasedIPGStream(input[0],input[1],input[2],input[3],input[4])
            session = Session([stream],False)
            session.sink(os.path.dirname(__file__)+f"/TimeBasedIPGStream_test_results/HF:{input[0]}_PG:{input[1]}_aveIPG:{input[2]}_IPGRange:{input[3]}_time:{input[4]}")
    
    def testTimeIPG(self):
        self.erroneousTests()
        inputs = self.genInputs()
        self.validTests(inputs)


class PktCountBasedPktRateStreamTest(unittest.TestCase):
    def __init__(self, methodName: str = "testPktCntPktRate") -> None:
        super().__init__(methodName)

    def genInputs(self) -> list[tuple[HeaderFrame, PayloadGenerator, float, int]]:
        headerFrames = [HeaderFrame.fromHeaderList([EthernetHeader(),Ipv4Header(),TCPHeader()]),HeaderFrame.fromHeaderList([EthernetHeader(),RoEHeader()]),HeaderFrame.fromHeaderList([EthernetHeader(),VLANHeaderSingle(),Ipv6Header(),UDPHeader()])]
        payloadGens = [PredefinedPayloadGenerator(randomFills=True, sizeStep=2),UserPayloadGenerator(["0x48656C6C6F576F726C64","0x4D794E616D65734973456C696A61684E69676761"])]
        numPackets = [1, 435, 1000]
        packetRates = [0.01, 7.72, 95.4, 2000]

        inputs = []

        for header in headerFrames:
            for payload in payloadGens:
                for num in numPackets:
                    for pr in packetRates:
                        input = (header, payload, pr, num)
                        inputs.append(input)
        return inputs
    
    def erroneousTests(self):
        default = (HeaderFrame.fromHeaderList([EthernetHeader(),Ipv4Header(),TCPHeader()]), PredefinedPayloadGenerator(randomFills=True, sizeStep=2), 60, 60)
        PktCountBasedPktRateStream(default[0],default[1],default[2],default[3])
        try:
            PktCountBasedPktRateStream(default[0],default[1],-77,default[3])
            raise AssertionError
        except (BaseException):
            pass
        try:
            PktCountBasedPktRateStream(default[0],default[1],0,default[3])
            raise AssertionError
        except (BaseException):
            pass
        try:
            PktCountBasedPktRateStream(default[0],default[1],default[2],-5.1)
            raise AssertionError
        except (BaseException):
            pass
        try:
            PktCountBasedPktRateStream(default[0],default[1],default[2],0)
            raise AssertionError
        except (BaseException):
            pass
    
    def validTests(self,inputs):
        for input in inputs:
            stream = PktCountBasedPktRateStream(input[0],input[1],input[2],input[3])
            session = Session([stream],False)
            session.sink(os.path.dirname(__file__)+f"/PktCountBasedPktRateStream_test_results/HF:{input[0]}_PG:{input[1]}_packetRate:{input[2]}_packetCount:{input[3]}")
    
    def testPktCntPktRate(self):
        self.erroneousTests()
        inputs = self.genInputs()
        self.validTests(inputs)


class TimeBasedPktRateStreamTest(unittest.TestCase):
    def __init__(self, methodName: str = "testTimePktRate") -> None:
        super().__init__(methodName)

    def genInputs(self) -> list[tuple[HeaderFrame, PayloadGenerator, float, float]]:
        headerFrames = [HeaderFrame.fromHeaderList([EthernetHeader(),Ipv4Header(),TCPHeader()]),HeaderFrame.fromHeaderList([EthernetHeader(),RoEHeader()]),HeaderFrame.fromHeaderList([EthernetHeader(),VLANHeaderSingle(),Ipv6Header(),UDPHeader()])]
        payloadGens = [PredefinedPayloadGenerator(randomFills=True, sizeStep=2),UserPayloadGenerator(["0x48656C6C6F576F726C64","0x4D794E616D65734973456C696A61684E69676761"])]
        times = [0.8, 15.5, 222.11, 600]
        packetRates = [0.5, 9.9, 123]

        inputs = []

        for header in headerFrames:
            for payload in payloadGens:
                for time in times:
                    for pr in packetRates:
                        input = (header, payload, pr, time)
                        inputs.append(input)
        return inputs
    
    def erroneousTests(self):
        default = (HeaderFrame.fromHeaderList([EthernetHeader(),Ipv4Header(),TCPHeader()]), PredefinedPayloadGenerator(randomFills=True, sizeStep=2), 60, 60)
        TimeBasedPktRateStream(default[0],default[1],default[2],default[3])
        try:
            TimeBasedPktRateStream(default[0],default[1],-41,default[3])
            raise AssertionError
        except (BaseException):
            pass
        try:
            TimeBasedPktRateStream(default[0],default[1],0,default[3])
            raise AssertionError
        except (BaseException):
            pass
        try:
            TimeBasedPktRateStream(default[0],default[1],default[2],20)
            raise AssertionError
        except (BaseException):
            pass
        try:
            TimeBasedPktRateStream(default[0],default[1],default[2],0)
            raise AssertionError
        except (BaseException):
            pass
        try:
            TimeBasedPktRateStream(default[0],default[1],default[2],16.1)
            raise AssertionError
        except (BaseException):
            pass
    
    def validTests(self,inputs):
        for input in inputs:
            stream = TimeBasedPktRateStream(input[0],input[1],input[2],input[3])
            session = Session([stream],False)
            session.sink(os.path.dirname(__file__)+f"/TimeBasedPktRateStream_test_results/HF:{input[0]}_PG:{input[1]}_packetRate:{input[2]}_time:{input[3]}")
    
    def testTimePktRate(self):
        self.erroneousTests()
        inputs = self.genInputs()
        self.validTests(inputs)

class ByteCountBasedByteRateStreamTest(unittest.TestCase):
    def __init__(self, methodName: str = "testByteCntByteRate") -> None:
        super().__init__(methodName)

    def genInputs(self) -> list[tuple[HeaderFrame, PayloadGenerator, float, int, bool]]:
        headerFrames = [HeaderFrame.fromHeaderList([EthernetHeader(),Ipv4Header(),TCPHeader()]),HeaderFrame.fromHeaderList([EthernetHeader(),RoEHeader()])]
        payloadGens = [PredefinedPayloadGenerator(randomFills=True, sizeStep=2, minSize=8,maxSize=32, initialSize=8),UserPayloadGenerator(["0x48656C6C6F576F726C64","0x4D794E616D65734973456C696A61684E69676761"])]
        byteRates = [10, 50.5, 30000]
        byteCounts = [128, 1025, 60124]

        inputs = []

        for header in headerFrames:
            for payload in payloadGens:
                for br in byteRates:
                    for bc in byteCounts:
                        input1 = (header, payload, br, bc, True)
                        input2 = (header, payload, br, bc, False)
                        inputs.append(input1)
                        inputs.append(input2)
        return inputs
    
    def erroneousTests(self):
        default = (HeaderFrame.fromHeaderList([EthernetHeader(),Ipv4Header(),TCPHeader()]), PredefinedPayloadGenerator(randomFills=True, sizeStep=2), 60, 1024, True)
        ByteCountBasedByteRateStream(default[0],default[1],default[2],default[3],default[4])
        try:
            ByteCountBasedByteRateStream(default[0],default[1],-3,default[3],default[4])
            raise AssertionError
        except (BaseException):
            pass
        try:
            ByteCountBasedByteRateStream(default[0],default[1],0,default[3],default[4])
            raise AssertionError
        except (BaseException):
            pass
        try:
            ByteCountBasedByteRateStream(default[0],default[1],default[2],-1,default[4])
            raise AssertionError
        except (BaseException):
            pass
        try:
            ByteCountBasedByteRateStream(default[0],default[1],default[2],0,default[4])
            raise AssertionError
        except (BaseException):
            pass
        try:
            ByteCountBasedByteRateStream(default[0],default[1],default[2],85,default[4])
            raise AssertionError
        except (BaseException):
            pass
        try:
            ByteCountBasedByteRateStream(default[0],default[1],default[2],200.1,default[4])
            raise AssertionError
        except (BaseException):
            pass
    
    def validTests(self,inputs):
        for input in inputs:
            stream = ByteCountBasedByteRateStream(input[0],input[1],input[2],input[3],input[4])
            session = Session([stream],False)
            session.sink(os.path.dirname(__file__)+f"/ByteCountBasedByteRateStream_test_results/HF:{input[0]}_PG:{input[1]}_byteRate:{input[2]}_byteCount:{input[3]}_fwp:{input[4]}")
    
    def testByteCntByteRate(self):
        self.erroneousTests()
        inputs = self.genInputs()
        self.validTests(inputs)

class TimeBasedByteRateStreamTest(unittest.TestCase):
    def __init__(self, methodName: str = "testTimeByteRate") -> None:
        super().__init__(methodName)

    def genInputs(self) -> list[tuple[HeaderFrame, PayloadGenerator, float, int, bool]]:
        headerFrames = [HeaderFrame.fromHeaderList([EthernetHeader(),Ipv4Header(),TCPHeader()]),HeaderFrame.fromHeaderList([EthernetHeader(),RoEHeader()])]
        payloadGens = [PredefinedPayloadGenerator(randomFills=True, sizeStep=2, minSize=8,maxSize=32, initialSize=8),UserPayloadGenerator(["0x48656C6C6F576F726C64","0x4D794E616D65734973456C696A61684E69676761"])]
        byteRates = [3, 64.1, 764.8]
        times = [0.8, 263, 888]

        inputs = []

        for header in headerFrames:
            for payload in payloadGens:
                for br in byteRates:
                    for time in times:
                        input = (header, payload, br, time)
                        inputs.append(input)
        return inputs
    
    def erroneousTests(self):
        default = (HeaderFrame.fromHeaderList([EthernetHeader(),Ipv4Header(),TCPHeader()]), PredefinedPayloadGenerator(randomFills=True, sizeStep=2), 60, 1024)
        TimeBasedByteRateStream(default[0],default[1],default[2],default[3])
        try:
            TimeBasedByteRateStream(default[0],default[1],-777,default[3])
            raise AssertionError
        except (BaseException):
            pass
        try:
            TimeBasedByteRateStream(default[0],default[1],0,default[3])
            raise AssertionError
        except (BaseException):
            pass
        try:
            TimeBasedByteRateStream(default[0],default[1],default[2],-18)
            raise AssertionError
        except (BaseException):
            pass
        try:
            TimeBasedByteRateStream(default[0],default[1],default[2],0)
            raise AssertionError
        except (BaseException):
            pass
    
    def validTests(self,inputs):
        for input in inputs:
            stream = TimeBasedByteRateStream(input[0],input[1],input[2],input[3])
            session = Session([stream],False)
            session.sink(os.path.dirname(__file__)+f"/TimeBasedByteRateStream_test_results/HF:{input[0]}_PG:{input[1]}_byteRate:{input[2]}_time:{input[3]}")
    
    def testTimeByteRate(self):
        self.erroneousTests()
        inputs = self.genInputs()
        self.validTests(inputs)

if __name__ == "__main__":
    unittest.main()
