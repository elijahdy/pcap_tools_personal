import unittest
import os
import sys
sys.path.append(os.getcwd())
from scapy.all import *
from pcap_generation import *

class PayloadTests(unittest.TestCase):

    def testPDPayloadInit(self):
        expPld1 = bytes.fromhex("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
        expPld2 = bytes.fromhex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff") 
        expPld3 = bytes.fromhex("00")
        expPld4 = bytes.fromhex("ff")
        expPld5 = bytes.fromhex("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
        self.assertEqual(PredefinedPayloadGenerator().fill,expPld1)
        self.assertEqual(PredefinedPayloadGenerator(initialFill=2**(64*8)-1).fill,expPld2)
        self.assertEqual(PredefinedPayloadGenerator(initialSize=1).fill,expPld3)
        self.assertEqual(PredefinedPayloadGenerator(initialSize=1,initialFill=255).fill,expPld4)
        self.assertEqual(PredefinedPayloadGenerator(initialSize=32,initialFill=int("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",16)).fill,expPld5)
        self.assertRaises(BaseException,PredefinedPayloadGenerator,initalFill=-1)
        self.assertRaises(BaseException,PredefinedPayloadGenerator,initalFill=2**(64*8))
        self.assertRaises(BaseException,PredefinedPayloadGenerator,initalSize=0)
        self.assertRaises(BaseException,PredefinedPayloadGenerator,initalSize=-1)
        self.assertRaises(BaseException,PredefinedPayloadGenerator,initalSize=129)
        self.assertRaises(BaseException,PredefinedPayloadGenerator,randomFills=True,fillStep=1)
        self.assertRaises(BaseException,PredefinedPayloadGenerator,randomSizes=True,sizeStep=1)
        self.assertRaises(BaseException,PredefinedPayloadGenerator,randomFills=True,fillStep=1)
        self.assertRaises(BaseException,PredefinedPayloadGenerator,minSize=0)
        self.assertRaises(BaseException,PredefinedPayloadGenerator,maxSize=0)
        self.assertRaises(BaseException,PredefinedPayloadGenerator,minSize=3,maxSize=2)
        self.assertRaises(BaseException,PredefinedPayloadGenerator,initialFill=4.5)
        self.assertRaises(BaseException,PredefinedPayloadGenerator,initialSize=4.5)
        self.assertRaises(BaseException,PredefinedPayloadGenerator,fillStep=4.5)
        self.assertRaises(BaseException,PredefinedPayloadGenerator,sizeStep=4.5)
        self.assertRaises(BaseException,PredefinedPayloadGenerator,minSize=4.5)
        self.assertRaises(BaseException,PredefinedPayloadGenerator,maxSize=4.5)
        self.assertRaises(BaseException,PredefinedPayloadGenerator,fillStep=2**(64*8))
        self.assertRaises(BaseException,PredefinedPayloadGenerator,sizeStep=97)

    def testPDPayloadfillMethods(self):
        payload = PredefinedPayloadGenerator()
        for i in range(100):
            prevFill = payload.fillAsInt
            payload.nextPayload()
            self.assertEqual(prevFill, payload.fillAsInt)
            self.assertEqual(payload.fillAsInt.to_bytes(payload.size,'big'),payload.fill)
        steps = [1,2**(32*8)-2,128000]
        for step in steps:
            payload = PredefinedPayloadGenerator(fillStep=step)
            for i in range(1000):
                prevFill = payload.fillAsInt
                payload.nextPayload()
                self.assertEqual((prevFill+step)%(2**(32*8)),payload.fillAsInt)
                self.assertLessEqual(payload.fillAsInt,2**(32*8)-1)
                self.assertGreaterEqual(payload.fillAsInt,0)
                self.assertEqual(payload.fillAsInt.to_bytes(payload.size,'big'),payload.fill)
            step = -step
            payload = PredefinedPayloadGenerator(fillStep=step)
            for i in range(1000):
                prevFill = payload.fillAsInt
                payload.nextPayload()
                result = prevFill + step
                if result >= 0:
                    self.assertEqual(payload.fillAsInt,result)
                else:
                    self.assertEqual(payload.fillAsInt,2**(32*8)+result)
                self.assertLessEqual(payload.fillAsInt,2**(32*8)-1)
                self.assertGreaterEqual(payload.fillAsInt,0)
                self.assertEqual(payload.fillAsInt.to_bytes(payload.size,'big'),payload.fill)
        payload = PredefinedPayloadGenerator(randomFills=True)
        for i in range(100):
            payload.nextPayload
            self.assertLessEqual(payload.fillAsInt,2**(32*8)-1)
            self.assertGreaterEqual(payload.fillAsInt,0)
            self.assertEqual(payload.fillAsInt.to_bytes(payload.size,'big'),payload.fill)
        
    def testPDPayloadSizeMethods(self):
        payload = PredefinedPayloadGenerator()
        for i in range(100):
            prevSize = payload.size
            payload.nextPayload()
            self.assertEqual(prevSize, payload.size)
            self.assertEqual(len(payload.fill),payload.size)
        maxMins = [(128,32),(2,1),(4096,2)]
        for pair in maxMins:
            steps = [pair[0]-pair[1]-1,pair[1],pair[1]+(pair[0]-pair[1])//2]
            for step in steps:
                payload = PredefinedPayloadGenerator(maxSize=pair[0],minSize=pair[1],initialSize=pair[1],sizeStep=step)
                for i in range(5000):
                    prevSize = payload.size
                    payload.nextPayload()
                    result = prevSize + step
                    if result > pair[0]:
                        self.assertEqual(pair[1]+(prevSize+step)%(pair[0]+1),payload.size)
                    else:
                        self.assertEqual(prevSize+step,payload.size)
                    self.assertLessEqual(payload.size,pair[0])
                    self.assertGreaterEqual(payload.size,pair[1])
                    self.assertEqual(len(payload.fill),payload.size)
                step = -step
                payload = PredefinedPayloadGenerator(maxSize=pair[0],minSize=pair[1],initialSize=pair[1],sizeStep=step)
                for i in range(5000):
                    prevSize = payload.size
                    payload.nextPayload()
                    result = prevSize + step
                    if result >= pair[1]:
                        self.assertEqual(payload.size,result)
                    else:
                        self.assertEqual(payload.size,pair[0]+(result-pair[1]+1))
                    self.assertLessEqual(payload.size,pair[0])
                    self.assertGreaterEqual(payload.size,pair[1])
                    self.assertEqual(len(payload.fill),payload.size)
        payload = PredefinedPayloadGenerator(randomSizes=True)
        for i in range(100):
            payload.nextPayload()
            self.assertLessEqual(payload.size,payload.maxSize)
            self.assertGreaterEqual(payload.size,payload.minSize)
            self.assertEqual(len(payload.fill),payload.size)
    
    def testPDNextPayload(self):
        fillSteps = [1,-1,2**(32*8)-2,-(2**(32*8)-2),128000,-128000]
        sizeSteps = [1, 17, 95, -1, -17, -95]
        for fillStep in fillSteps:
            for sizeStep in sizeSteps:
                payload = PredefinedPayloadGenerator(fillStep=fillStep,sizeStep=sizeStep)
                for i in range(100):
                    prevPayload = copy.deepcopy(payload)
                    payload.nextPayload()
                    if fillStep > 0:
                        self.assertEqual((prevPayload.fillAsInt+fillStep)%(2**(32*8)),payload.fillAsInt)
                        self.assertLessEqual(payload.fillAsInt,2**(32*8)-1)
                        self.assertGreaterEqual(payload.fillAsInt,0)
                        self.assertEqual(payload.fillAsInt.to_bytes(payload.size,'big'),payload.fill)
                    else:
                        result = prevPayload.fillAsInt + fillStep
                        if result >= 0:
                            self.assertEqual(payload.fillAsInt,result)
                        else:
                            self.assertEqual(payload.fillAsInt,2**(32*8)+result)
                        self.assertLessEqual(payload.fillAsInt,2**(32*8)-1)
                        self.assertGreaterEqual(payload.fillAsInt,0)
                        self.assertEqual(payload.fillAsInt.to_bytes(payload.size,'big'),payload.fill)
                    result = prevPayload.size + sizeStep
                    if sizeStep > 0:
                        if result > payload.maxSize:
                            self.assertEqual(payload.minSize+(prevPayload.size+sizeStep)%(payload.maxSize+1),payload.size)
                        else:
                            self.assertEqual(prevPayload.size+sizeStep,payload.size)
                        self.assertLessEqual(payload.size,payload.maxSize)
                        self.assertGreaterEqual(payload.size,payload.minSize)
                        self.assertEqual(len(payload.fill),payload.size)
                    else:
                        if result >= payload.minSize:
                            self.assertEqual(payload.size,result)
                        else:
                            self.assertEqual(payload.size,payload.maxSize+(result-payload.minSize+1))
                        self.assertLessEqual(payload.size,payload.maxSize)
                        self.assertGreaterEqual(payload.size,payload.minSize)
                        self.assertEqual(len(payload.fill),payload.size)
        steps = [1, -1, 66, -66]
        for step in steps:
            payload = PredefinedPayloadGenerator(randomFills=True,sizeStep=step)
            for i in range(100):
                prevPayload = copy.deepcopy(payload)
                payload.nextPayload()
                self.assertLessEqual(payload.fillAsInt,2**(32*8)-1)
                self.assertGreaterEqual(payload.fillAsInt,0)
                self.assertEqual(payload.fillAsInt.to_bytes(payload.size,'big'),payload.fill)
                result = prevPayload.size + step
                if step > 0:
                    if result > payload.maxSize:
                        self.assertEqual(payload.minSize+(prevPayload.size+step)%(payload.maxSize+1),payload.size)
                    else:
                        self.assertEqual(prevPayload.size+step,payload.size)
                    self.assertLessEqual(payload.size,payload.maxSize)
                    self.assertGreaterEqual(payload.size,payload.minSize)
                    self.assertEqual(len(payload.fill),payload.size)
                else:
                    if result >= payload.minSize:
                        self.assertEqual(payload.size,result)
                    else:
                        self.assertEqual(payload.size,payload.maxSize+(result-payload.minSize+1))
                    self.assertLessEqual(payload.size,payload.maxSize)
                    self.assertGreaterEqual(payload.size,payload.minSize)
                    self.assertEqual(len(payload.fill),payload.size)
            payload = PredefinedPayloadGenerator(randomSizes=True,fillStep=step)
            for i in range(100):
                prevPayload = copy.deepcopy(payload)
                payload.nextPayload()
                self.assertLessEqual(payload.size,payload.maxSize)
                self.assertGreaterEqual(payload.size,payload.minSize)
                self.assertEqual(len(payload.fill),payload.size)
                if step > 0:
                    self.assertEqual((prevPayload.fillAsInt+step)%(2**(32*8)),payload.fillAsInt)
                    self.assertLessEqual(payload.fillAsInt,2**(32*8)-1)
                    self.assertGreaterEqual(payload.fillAsInt,0)
                    self.assertEqual(payload.fillAsInt.to_bytes(payload.size,'big'),payload.fill)
                else:
                    result = prevPayload.fillAsInt + step
                    if result >= 0:
                        self.assertEqual(payload.fillAsInt,result)
                    else:
                        self.assertEqual(payload.fillAsInt,2**(32*8)+result)
                    self.assertLessEqual(payload.fillAsInt,2**(32*8)-1)
                    self.assertGreaterEqual(payload.fillAsInt,0)
                    self.assertEqual(payload.fillAsInt.to_bytes(payload.size,'big'),payload.fill)
    
    def testUsrPldBytes(self):
        validStrs = ["0b11111111","0xff","0b00000000","0x00","0b10101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010",
                      "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"]
        invalidStrs = ["0b0","0x1","0x12345","0x1234567","0b1010","0b1010101","0b10101010101","10101010","af1321","£Fl*i","0x1234567890abcdeg","0b10011002","https://wooweewoowah.com"]
        for string in validStrs:
            self.assertEqual(UserPayloadGenerator.validateByteString(string), True)
        for string in invalidStrs:
            self.assertRaises(BaseException,UserPayloadGenerator.validateByteString,string)
        expBytes = [int(1).to_bytes(4,'big'),int(2**(64*8)-1).to_bytes(64,'big'),bytes.fromhex("1357913151719212")]
        byteStrings = ["0b00000000000000000000000000000001","0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff","0x1357913151719212"]
        for i,byteString in enumerate(byteStrings):
            self.assertEqual(expBytes[i],UserPayloadGenerator.byteStringToFill(byteString))

    
    def testUsrNextPayload(self):
        testLists = [["0x55"],["0x01","0x02","0x03","0x04","0x05","0x06","0x07","0x08","0x09","0x0a","0x0b","0x0c","0x0d","0x0e","0x0f","0x00"],["0xff","0xff","0xff","0x00"]]
        payloadGen1 = UserPayloadGenerator(testLists[0])
        payloadGen2 = UserPayloadGenerator(testLists[1])
        payloadGen3 = UserPayloadGenerator(testLists[2])
        expPlds1 = [bytes.fromhex("55"),bytes.fromhex("55"),bytes.fromhex("55"),bytes.fromhex("55"),bytes.fromhex("55"),
                    bytes.fromhex("55"),bytes.fromhex("55"),bytes.fromhex("55"),bytes.fromhex("55"),bytes.fromhex("55")]
        expPlds2 = [bytes.fromhex("01"),bytes.fromhex("02"),bytes.fromhex("03"),bytes.fromhex("04"),bytes.fromhex("05"),bytes.fromhex("06"),bytes.fromhex("07"),bytes.fromhex("08"),
                    bytes.fromhex("09"),bytes.fromhex("0a"),bytes.fromhex("0b"),bytes.fromhex("0c"),bytes.fromhex("0d"),bytes.fromhex("0e"),bytes.fromhex("0f"),bytes.fromhex("00"),
                    bytes.fromhex("01"),bytes.fromhex("02"),bytes.fromhex("03"),bytes.fromhex("04"),bytes.fromhex("05"),bytes.fromhex("06"),bytes.fromhex("07"),bytes.fromhex("08"),
                    bytes.fromhex("09"),bytes.fromhex("0a"),bytes.fromhex("0b"),bytes.fromhex("0c"),bytes.fromhex("0d"),bytes.fromhex("0e"),bytes.fromhex("0f"),bytes.fromhex("00")]
        expPlds3 = [bytes.fromhex("ff"),bytes.fromhex("ff"),bytes.fromhex("ff"),bytes.fromhex("00"),bytes.fromhex("ff"),bytes.fromhex("ff"),bytes.fromhex("ff"),bytes.fromhex("00")]
        self.assertEqual(payloadGen1.fill,expPlds1[0])
        self.assertEqual(payloadGen2.fill,expPlds2[0])
        self.assertEqual(payloadGen3.fill,expPlds3[0])
        for expPld in expPlds1[1:]:
            payloadGen1.nextPayload()
            self.assertEqual(expPld,payloadGen1.fill)
        for expPld in expPlds2[1:]:
            payloadGen2.nextPayload()
            self.assertEqual(expPld,payloadGen2.fill)
        for expPld in expPlds3[1:]:
            payloadGen3.nextPayload()
            self.assertEqual(expPld,payloadGen3.fill)

if __name__ == "__main__":
    unittest.main()
