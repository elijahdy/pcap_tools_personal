import unittest
import os
import sys
#run from cwd=pcap_tools_personal
sys.path.append(os.getcwd())
from scapy.all import *
from pcap_generation import *

class HeadersTest(unittest.TestCase):
    def testEthernet(self):
        tc_1 = "1A:2B:3C:4D:5E:00"
        tc_2 = "1a:2b:3c:4d:5e:00"
        tc_3 = "ff:ff:ff:ff:ff:fe"
        tc_4 = "00:00:00:00:00:01"
        tc_5 =  ':'.join(['{:02x}'.format(random.randint(0, 255)) for _ in range(6)])
        tc_6 =  ':'.join(['{:02x}'.format(random.randint(0, 255)) for _ in range(6)])
        tce_1 = "111:22:33:44:55:66"
        tce_2 = "77:66:55:44:33:22:11"
        tce_3 = "0g:11:22:33:44:55"
        exp_12 = int("0x1A2B3C4D5E001A2B3C4D5E009000",16).to_bytes(14,'big')
        exp_34 = int("0xfffffffffffe0000000000019000",16).to_bytes(14,'big')
        exp_56 = int(f"0x{tc_5.replace(':','')}{tc_6.replace(':','')}9000",16).to_bytes(14,'big')
        self.assertEqual(EthernetHeader().content, Ether(src="00:00:00:00:00:00",dst="ff:ff:ff:ff:ff:ff"))
        self.assertEqual(bytes(EthernetHeader(srcMAC=[tc_1],dstMAC=[tc_2]).content),exp_12)
        self.assertEqual(bytes(EthernetHeader(srcMAC=[tc_4],dstMAC=[tc_3]).content),exp_34)
        self.assertEqual(bytes(EthernetHeader(srcMAC=[tc_6],dstMAC=[tc_5]).content),exp_56)
        self.assertRaises(ValueError,EthernetHeader,srcMAC=[tc_1],dstMAC=[tce_1])
        self.assertRaises(ValueError,EthernetHeader,srcMAC=[tce_2],dstMAC=[tc_2])
        self.assertRaises(ValueError,EthernetHeader,srcMAC=[tc_2],dstMAC=[tce_3])
    
    def testVLAN(self):
        exp_1 = int("0xefff0000",16).to_bytes(4,'big')
        exp_2 = int("0x00000000",16).to_bytes(4,'big')
        exp_3 = int("0x87778100a6660000",16).to_bytes(8,'big')
        self.assertEqual(VLANHeaderSingle().content, Dot1Q())
        self.assertEqual(bytes(VLANHeaderSingle(pcp=[7],vid=[int("0xfff",16)]).content),exp_1)
        self.assertEqual(bytes(VLANHeaderSingle(pcp=[0],vid=[0]).content),exp_2)
        self.assertEqual(bytes(VLANHeaderDouble(pcp=[4,5],vid=[int("0x777",16),int("0x666",16)]).content),exp_3)
        self.assertRaises(BaseException,VLANHeaderSingle,pcp=[8])
        self.assertRaises(BaseException,VLANHeaderSingle,pcp=[-1])
        self.assertRaises(BaseException,VLANHeaderSingle,pcp=[255])
        self.assertRaises(BaseException,VLANHeaderSingle,vid=[4096])
        self.assertRaises(BaseException,VLANHeaderSingle,vid=[-1])
        self.assertRaises(BaseException,VLANHeaderSingle,vid=[99999])
        self.assertRaises(BaseException,VLANHeaderDouble,pcp=[8,8])
        self.assertRaises(BaseException,VLANHeaderDouble,pcp=[-1,-1])
        self.assertRaises(BaseException,VLANHeaderDouble,pcp=[255,255])
        self.assertRaises(BaseException,VLANHeaderDouble,vid=[4096,4096])
        self.assertRaises(BaseException,VLANHeaderDouble,vid=[-1,-1])
        self.assertRaises(BaseException,VLANHeaderDouble,vid=[1,2,3])
        self.assertRaises(BaseException,VLANHeaderDouble,pcp=[5,4,3,2,1])


    def testMPLS(self):
        exp_1 = bytes.fromhex("ffffffff")
        exp_2 = bytes.fromhex("00000100")
        exp_3 = bytes.fromhex("12345977")
        self.assertEqual(bytes(MPLSHeader(label=[2**20-1],qos=[7],ttl=[255]).content),exp_1)
        self.assertEqual(bytes(MPLSHeader(label=[0],qos=[0],ttl=[0]).content),exp_2)
        self.assertEqual(bytes(MPLSHeader(label=[int("12345",16)],qos=[4],ttl=[int("77",16)]).content),exp_3)
        self.assertRaises(BaseException,MPLSHeader,label=[2**20],qos=[4],ttl=[int("77",16)])
        self.assertRaises(BaseException,MPLSHeader,label=[-1],qos=[4],ttl=[int("77",16)])
        self.assertRaises(BaseException,MPLSHeader,label=[int("12345",16)],qos=[8],ttl=[int("77",16)])
        self.assertRaises(BaseException,MPLSHeader,label=[int("12345",16)],qos=[-1],ttl=[int("77",16)])
        self.assertRaises(BaseException,MPLSHeader,label=[int("12345",16)],qos=[4],ttl=[256])
        self.assertRaises(BaseException,MPLSHeader,label=[int("12345",16)],qos=[4],ttl=[-1])
    
    def testGTPv2(self):
        exp_1 = bytes.fromhex("58ff0004ffffffff")
        exp_2 = bytes.fromhex("5800000400000000")
        exp_3 = bytes.fromhex("581f000412345678")
        self.assertEqual(bytes(GTPv2Header(messageType=[255],teid=[4294967295]).content)[:8],exp_1)
        self.assertEqual(bytes(GTPv2Header(messageType=[0],teid=[0]).content)[:8],exp_2)
        self.assertEqual(bytes(GTPv2Header(messageType=[31],teid=[int("12345678",16)]).content)[:8],exp_3)
        self.assertRaises(BaseException,GTPv2Header,messageType=[256],teid=[0])
        self.assertRaises(BaseException,GTPv2Header,messageType=[-1],teid=[0])
        self.assertRaises(BaseException,GTPv2Header,messageType=[0],teid=[4294967296])
        self.assertRaises(BaseException,GTPv2Header,messageType=[0],teid=[-1])
    
    def testGTPv1(self):
        exp_1 = bytes.fromhex("30ff0000ffffffff")
        exp_2 = bytes.fromhex("3000000000000000")
        exp_3 = bytes.fromhex("301f000012345678")
        self.assertEqual(bytes(GTPv1Header(messageType=[255],teid=[4294967295]).content)[:8],exp_1)
        self.assertEqual(bytes(GTPv1Header(messageType=[0],teid=[0]).content)[:8],exp_2)
        self.assertEqual(bytes(GTPv1Header(messageType=[31],teid=[int("12345678",16)]).content)[:8],exp_3)
        self.assertRaises(BaseException,GTPv1Header,messageType=[256],teid=[0])
        self.assertRaises(BaseException,GTPv1Header,messageType=[-1],teid=[0])
        self.assertRaises(BaseException,GTPv1Header,messageType=[0],teid=[4294967296])
        self.assertRaises(BaseException,GTPv1Header,messageType=[0],teid=[-1])
    
    def testNextHeader(self):
        ethenetHeader = EthernetHeader(srcMAC=["aa:aa:aa:aa:aa:aa","bb:bb:bb:bb:bb:bb"], dstMAC=["aa:aa:aa:aa:aa:aa","bb:bb:bb:bb:bb:bb","cc:cc:cc:cc:cc:cc"])
        expBytes = [bytes.fromhex("aaaaaaaaaaaaaaaaaaaaaaaa"),bytes.fromhex("bbbbbbbbbbbbbbbbbbbbbbbb"),bytes.fromhex("ccccccccccccaaaaaaaaaaaa"),bytes.fromhex("aaaaaaaaaaaabbbbbbbbbbbb")]
        for exp in expBytes:
            self.assertEqual(exp,bytes(ethenetHeader.content)[:12])
            ethenetHeader.nextHeader()
        vlanHeaderS = VLANHeaderSingle(pcp=[1,2,3])
        vlanHeaderD = VLANHeaderDouble(vid=[2,2,3,3,4,4])
        expBytesS = [bytes.fromhex("20010000"),bytes.fromhex("40010000"),bytes.fromhex("60010000")]
        expBytesD = [bytes.fromhex("0002810000020000"),bytes.fromhex("0003810000030000"),bytes.fromhex("0004810000040000")]
        for i in range(len(expBytesS)):
            self.assertEqual(expBytesS[i],bytes(vlanHeaderS.content))
            vlanHeaderS.nextHeader()
            self.assertEqual(expBytesD[i],bytes(vlanHeaderD.content))
            vlanHeaderD.nextHeader()


class LayerTests(unittest.TestCase):

    def testLayer2(self):
        expHeaders1 = [EthernetHeader()]
        expHeaders2 = [EthernetHeader(),VLANHeaderSingle()]
        expHeaders3 = [EthernetHeader(),MPLSHeader()]
        expHeaders4 = [EthernetHeader(),RoEHeader()]
        expHeaders5 = [EthernetHeader(),ECPRIHeader()]
        expHeaders6 = [EthernetHeader(),VLANHeaderSingle(),MPLSHeader()]
        expHeaders7 = [EthernetHeader(),VLANHeaderSingle(),RoEHeader()]
        expHeaders8 = [EthernetHeader(),VLANHeaderSingle(),ECPRIHeader()]
        self.compareHeaderLists(Layer2.default().headers,expHeaders1)
        self.compareHeaderLists(Layer2([EthernetHeader()]).headers,expHeaders1)
        self.compareHeaderLists(Layer2([EthernetHeader(),VLANHeaderSingle()]).headers,expHeaders2)
        self.compareHeaderLists(Layer2([EthernetHeader(),MPLSHeader()]).headers,expHeaders3)
        self.compareHeaderLists(Layer2([EthernetHeader(),RoEHeader()]).headers,expHeaders4)
        self.compareHeaderLists(Layer2([EthernetHeader(),ECPRIHeader()]).headers,expHeaders5)
        self.compareHeaderLists(Layer2([EthernetHeader(),VLANHeaderSingle(),MPLSHeader()]).headers,expHeaders6)
        self.compareHeaderLists(Layer2([EthernetHeader(),VLANHeaderSingle(),RoEHeader()]).headers,expHeaders7)
        self.compareHeaderLists(Layer2([EthernetHeader(),VLANHeaderSingle(),ECPRIHeader()]).headers,expHeaders8)
        self.compareHeaderLists(Layer2.autofillFromHeader(EthernetHeader()).headers,expHeaders1)
        self.compareHeaderLists(Layer2.autofillFromHeader(VLANHeaderSingle()).headers,expHeaders2)
        self.compareHeaderLists(Layer2.autofillFromHeader(MPLSHeader()).headers,expHeaders3)
        self.compareHeaderLists(Layer2.autofillFromHeader(RoEHeader()).headers,expHeaders4)
        self.compareHeaderLists(Layer2.autofillFromHeader(ECPRIHeader()).headers,expHeaders5)
        self.assertRaises(BaseException,Layer2.autofillFromHeader,Ipv4Header())
        self.assertRaises(BaseException,Layer2.autofillFromHeader,UDPHeader())
        noNoCombos = [[Ipv4Header()],[TCPHeader()],[GTPv1Header()],[VLANHeaderSingle()],[MPLSHeader()],[RoEHeader()],
                      [ECPRIHeader(),EthernetHeader()],[MPLSHeader(),VLANHeaderSingle()],[VLANHeaderSingle(),EthernetHeader()],
                      [EthernetHeader(),MPLSHeader(),VLANHeaderSingle()],[VLANHeaderSingle(),MPLSHeader(),ECPRIHeader()],
                      [EthernetHeader(),VLANHeaderSingle(),MPLSHeader(),ECPRIHeader()]]
        for nonoCombo in noNoCombos:
            self.assertRaises(BaseException,Layer2,nonoCombo)

    def testLayer3(self):
        expHeaders1 = [Ipv4Header()]
        expHeaders2 = [Ipv6Header()]
        self.compareHeaderLists(Layer3.default().headers,expHeaders1)
        self.compareHeaderLists(Layer3([Ipv4Header()]).headers,expHeaders1)
        self.compareHeaderLists(Layer3([Ipv6Header()]).headers,expHeaders2)
        self.assertRaises(BaseException,Layer3,[Ipv4Header(),Ipv6Header()])
        self.assertRaises(BaseException,Layer3,[Ipv6Header(),Ipv4Header()])
        self.assertRaises(BaseException,Layer3,[EthernetHeader()])
        self.assertRaises(BaseException,Layer3,[UDPHeader()])
    
    def testLayer4(self):
        expHeaders1 = [TCPHeader()]
        expHeaders2 = [UDPHeader()]
        expHeaders3 = [UDPHeader(),GTPv1Header()]
        expHeaders4 = [UDPHeader(),GTPv2Header()]
        expHeaders5 = [UDPHeader(),ECPRIHeader()]
        expHeaders6 = [TCPHeader(),GTPv2Header()]
        self.compareHeaderLists(Layer4.default().headers,expHeaders1)
        self.compareHeaderLists(Layer4([TCPHeader()]).headers,expHeaders1)
        self.compareHeaderLists(Layer4([UDPHeader()]).headers,expHeaders2)
        self.compareHeaderLists(Layer4([UDPHeader(),GTPv1Header()]).headers,expHeaders3)
        self.compareHeaderLists(Layer4([UDPHeader(),GTPv2Header()]).headers,expHeaders4)
        self.compareHeaderLists(Layer4([UDPHeader(),ECPRIHeader()]).headers,expHeaders5)
        self.compareHeaderLists(Layer4([TCPHeader(),GTPv2Header()]).headers,expHeaders6)
        self.compareHeaderLists(Layer4.autofillFromHeader(TCPHeader()).headers,expHeaders1)
        self.compareHeaderLists(Layer4.autofillFromHeader(UDPHeader()).headers,expHeaders2)
        self.compareHeaderLists(Layer4.autofillFromHeader(GTPv1Header()).headers,expHeaders3)
        self.compareHeaderLists(Layer4.autofillFromHeader(GTPv2Header()).headers,expHeaders4)
        self.compareHeaderLists(Layer4.autofillFromHeader(ECPRIHeader()).headers,expHeaders5)
        self.assertRaises(BaseException,Layer4.autofillFromHeader,VLANHeaderSingle())
        self.assertRaises(BaseException,Layer4.autofillFromHeader,Ipv6Header())
        noNoCombos = [[Ipv6Header()],[EthernetHeader()],[GTPv1Header()],[GTPv2Header()],[ECPRIHeader()],
                      [ECPRIHeader(),UDPHeader()],[TCPHeader(),GTPv1Header()],[UDPHeader(),TCPHeader()],[TCPHeader(),UDPHeader()],[GTPv1Header(),GTPv2Header()],
                      [UDPHeader(),TCPHeader(),GTPv2Header()],[TCPHeader(),ECPRIHeader(),GTPv1Header()]]
        for nonoCombo in noNoCombos:
            self.assertRaises(BaseException,Layer4,nonoCombo)

    def testHeaderFrame(self):
        layer2 = Layer2([EthernetHeader(),VLANHeaderSingle(),RoEHeader()])
        layer3 = Layer3([Ipv6Header()])
        layer4 = Layer4([TCPHeader(),GTPv2Header()])
        expHeaders1 = [EthernetHeader(),VLANHeaderSingle(),RoEHeader()]
        expHeaders2 = [EthernetHeader(),VLANHeaderSingle(),RoEHeader(),Ipv6Header()]
        expHeaders3 = [EthernetHeader(),VLANHeaderSingle(),RoEHeader(),Ipv6Header(),TCPHeader(),GTPv2Header()]
        self.compareHeaderLists(HeaderFrame([layer2]).headers,expHeaders1)
        self.compareHeaderLists(HeaderFrame([layer2,layer3]).headers,expHeaders2)
        self.compareHeaderLists(HeaderFrame([layer2,layer3,layer4]).headers,expHeaders3)
        self.assertRaises(BaseException,HeaderFrame,[layer3])
        self.assertRaises(BaseException,HeaderFrame,[layer4])
        self.assertRaises(BaseException,HeaderFrame,[layer3,layer4])
        self.assertRaises(BaseException,HeaderFrame,[layer4,layer3])
        self.assertRaises(BaseException,HeaderFrame,[layer2,layer4])
        self.assertRaises(BaseException,HeaderFrame,[layer2,layer4,layer3])
        self.assertRaises(BaseException,HeaderFrame,[layer2,layer2])
        expAutoFillLayer2 = [EthernetHeader(),VLANHeaderSingle(),RoEHeader()]
        expAutoFillLayer3 = [EthernetHeader(),Ipv6Header()]
        expAutoFillLayer4 = [EthernetHeader(), Ipv4Header(), TCPHeader(), GTPv2Header()]
        self.compareHeaderLists(HeaderFrame.autofillFromLayer(layer2).headers,expAutoFillLayer2)
        self.compareHeaderLists(HeaderFrame.autofillFromLayer(layer3).headers,expAutoFillLayer3)
        self.compareHeaderLists(HeaderFrame.autofillFromLayer(layer4).headers,expAutoFillLayer4)
        expAutoEther = [EthernetHeader()]
        expAutoVLAN = [EthernetHeader(), VLANHeaderSingle()]
        expAutoMPLS = [EthernetHeader(), MPLSHeader()]
        expAutoRoE = [EthernetHeader(), RoEHeader()]
        expAutoECPRI = [EthernetHeader(), ECPRIHeader()]
        expAutoIPv4 = [EthernetHeader(), Ipv4Header()]
        expAutoIPv6 = [EthernetHeader(), Ipv6Header()]
        expAutoUDP = [EthernetHeader(), Ipv4Header(), UDPHeader()]
        expAutoTCP = [EthernetHeader(), Ipv4Header(), TCPHeader()]
        expAutoGTPv1 = [EthernetHeader(), Ipv4Header(), UDPHeader(), GTPv1Header()]
        expAutoGTPv2 = [EthernetHeader(), Ipv4Header(), UDPHeader(), GTPv2Header()]
        self.compareHeaderLists(HeaderFrame.autofillFromHeader(EthernetHeader()).headers,expAutoEther)
        self.compareHeaderLists(HeaderFrame.autofillFromHeader(VLANHeaderSingle()).headers,expAutoVLAN)
        self.compareHeaderLists(HeaderFrame.autofillFromHeader(MPLSHeader()).headers,expAutoMPLS)
        self.compareHeaderLists(HeaderFrame.autofillFromHeader(RoEHeader()).headers,expAutoRoE)
        self.compareHeaderLists(HeaderFrame.autofillFromHeader(ECPRIHeader()).headers,expAutoECPRI)
        self.compareHeaderLists(HeaderFrame.autofillFromHeader(Ipv4Header()).headers,expAutoIPv4)
        self.compareHeaderLists(HeaderFrame.autofillFromHeader(Ipv6Header()).headers,expAutoIPv6)
        self.compareHeaderLists(HeaderFrame.autofillFromHeader(UDPHeader()).headers,expAutoUDP)
        self.compareHeaderLists(HeaderFrame.autofillFromHeader(TCPHeader()).headers,expAutoTCP)
        self.compareHeaderLists(HeaderFrame.autofillFromHeader(GTPv1Header()).headers,expAutoGTPv1)
        self.compareHeaderLists(HeaderFrame.autofillFromHeader(GTPv2Header()).headers,expAutoGTPv2)
 
    def compareHeaderLists(self, list1,list2):
        self.assertEqual(len(list1),len(list2))
        for i in range(len(list1)):
            if isinstance(list1[i],GTPv2Header):
                self.assertEqual(bytes(list1[i].content)[:8],bytes(list2[i].content)[:8])
            else:
                self.assertEqual(bytes(list1[i].content),bytes(list2[i].content))
    
    def testFromHeaderList(self):
        list1 = [EthernetHeader(),Ipv4Header(),TCPHeader()]
        list2 = [EthernetHeader(),RoEHeader()]
        list3 = [EthernetHeader(),MPLSHeader(),Ipv4Header(),TCPHeader(),GTPv2Header()]
        list4 = [EthernetHeader(), ECPRIHeader()]
        list5 = [EthernetHeader(),Ipv6Header(),UDPHeader(),ECPRIHeader()]
        list6 = [Ipv4Header()]
        list7 = [VLANHeaderDouble,Ipv6Header()]
        list8 = [EthernetHeader(),UDPHeader()]
        list9 = [EthernetHeader(),Ipv4Header(),MPLSHeader()]
        h1 = HeaderFrame.fromHeaderList([EthernetHeader(),Ipv4Header(),TCPHeader()])
        h2 = HeaderFrame.fromHeaderList([EthernetHeader(),RoEHeader()])
        h3 = HeaderFrame.fromHeaderList([EthernetHeader(),MPLSHeader(),Ipv4Header(),TCPHeader(),GTPv2Header()])
        h4 = HeaderFrame.fromHeaderList([EthernetHeader(),ECPRIHeader()])
        h5 = HeaderFrame.fromHeaderList([EthernetHeader(),Ipv6Header(),UDPHeader(),ECPRIHeader()])
        self.compareHeaderLists(h1.headers,list1)
        self.compareHeaderLists(h2.headers,list2)
        self.compareHeaderLists(h3.headers,list3)
        self.compareHeaderLists(h4.headers,list4)
        self.compareHeaderLists(h5.headers,list5)
        self.assertRaises(BaseException,HeaderFrame.fromHeaderList,list6)
        self.assertRaises(BaseException,HeaderFrame.fromHeaderList,list7)
        self.assertRaises(BaseException,HeaderFrame.fromHeaderList,list8)
        self.assertRaises(BaseException,HeaderFrame.fromHeaderList,list9)

if __name__ == "__main__":
    unittest.main()