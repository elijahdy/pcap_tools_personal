import os
from sys import path
path.append(os.path.dirname(__file__))
from scapy.all import *
from scapy.utils import wrpcap
from re import fullmatch
from ipaddress import IPv4Address, IPv6Address
from warnings import warn
from random import randint
from numpy.random import normal
from scapy.contrib.mpls import *
from scapy.contrib.gtp_v2 import GTPHeader as GTPv2
from scapy.contrib.gtp import GTPHeader as GTPv1
from additional_scapy_packets import *
from scapy.layers.l2 import Dot1Q
from scapy.layers.inet import TCP




class Header():
    """An abstract class for a packet protocol header."""

    def __init__(self, **headerParams):
        """initialises header specific parameters"""
        self.currentIndex = 0
        for key in headerParams.keys():
            if headerParams[key] != None:
                self.params[key] = headerParams[key]
    
    def checkLayer(self):
        """returns the layer which the header object belongs to"""
        if isinstance(self, ECPRIHeader):
            #eCPRI can be layer 2 or 4 so needs special classification
            return -3
        elif isinstance(self, Layer2Header):
            return 2
        elif isinstance(self, Layer3Header):
            return 3
        else:
            return 4
    
    def nextHeader(self):
        """change to the next header configurations in the given lists"""
        self.currentIndex += 1


class Layer2Header(Header):
    """An abstract class for layer 2 headers e.g. Ethernet"""
    def __init__(self, **headerParams):
        super().__init__(**headerParams)


class Layer3Header(Header):
    """An abstract class for layer 3 headers e.g. IPv4"""
    def __init__(self, **headerParams):
        super().__init__(**headerParams)
        for key in self.params.keys():
            if key != 'srcIP' and key != 'dstIP' and key != 'protocol':
                raise ValueError("Invalid IP Parameters")


class Layer4Header(Header):
    """An abstract class for layer 4 headers e.g. TCP"""
    def __init__(self, **headerParams):
        super().__init__(**headerParams)


class EthernetHeader(Layer2Header):
    """An Ethernet header."""
    def __init__(self, **headerParams):
        """validates Ethernet parameters and generates the bytes of the header with scapy, \n other header constructors do the same for their specific header type"""
        self.params = {}
        self.params['srcMAC'] = ["00:00:00:00:00:00"]
        self.params['dstMAC'] = ["ff:ff:ff:ff:ff:ff"]
        self.params['type'] = None #ethernet type set to None initially because the scapy autofill of this field fails if it's set by the user initially
        super().__init__(**headerParams)
        for key in self.params.keys():
            if key != 'srcMAC' and key != 'dstMAC' and key != 'type':
                raise ValueError("Invalid Ethernet Parameters")
        if  (any([not(fullmatch(r'([0-9a-fA-F]{2}[:]){5}[0-9a-fA-F]{2}',srcMAC)) for srcMAC in self.params['srcMAC']]) or 
            any([not(fullmatch(r'([0-9a-fA-F]{2}[:]){5}[0-9a-fA-F]{2}',dstMAC)) for dstMAC in self.params['dstMAC']])): 
            raise ValueError("Invalid Ethernet Parameters")
        if self.params['type'] != None:
            if any([tp < 0 or tp > 65535 for tp in self.params['type']]):
                raise ValueError("Invalid Ethernet Parameters")
            self.content: Packet = Ether(src=self.params['srcMAC'][self.currentIndex],
                                            dst=self.params['dstMAC'][self.currentIndex],
                                            type=self.params['type'][self.currentIndex])
        else:
            self.content: Packet = Ether(src=self.params['srcMAC'][self.currentIndex],
                                            dst=self.params['dstMAC'][self.currentIndex])
        
    def nextHeader(self):
        super().nextHeader()
        if self.params['type'] != None:
            self.content: Packet = Ether(src=self.params['srcMAC'][self.currentIndex%len(self.params['srcMAC'])],
                                        dst=self.params['dstMAC'][self.currentIndex%len(self.params['dstMAC'])],
                                        type=self.params['type'][self.currentIndex%len(self.params['type'])])
        else:
            self.content: Packet = Ether(src=self.params['srcMAC'][self.currentIndex%len(self.params['srcMAC'])],
                                        dst=self.params['dstMAC'][self.currentIndex%len(self.params['dstMAC'])])

class VLANHeader(Layer2Header):
    """An abstract VLAN header class."""

    def __init__(self, **headerParams):
        super().__init__(**headerParams)
        for key in self.params.keys():
            if key != 'pcp' and key != 'vid':
                raise ValueError("Invalid VLAN Parameters")    

class VLANHeaderSingle(VLANHeader):
    """A single tagged VLAN header."""

    def __init__(self, **headerParams):
        self.params = {}
        self.params['pcp'] = [0]
        self.params['vid'] = [1]
        super().__init__(**headerParams)
        if (any([pcp < 0 or pcp > 7 for pcp in self.params['pcp']]) or
            any([vid < 0 or vid > 4095 for vid in self.params['vid']])):
            raise ValueError("Invalid VLAN Parameters")
        self.content: Packet = Dot1Q(prio=self.params['pcp'][self.currentIndex],
                                     vlan=self.params['vid'][self.currentIndex])

    def nextHeader(self):
        super().nextHeader()
        self.content: Packet = Dot1Q(prio=self.params['pcp'][self.currentIndex%len(self.params['pcp'])],
                                     vlan=self.params['vid'][self.currentIndex%len(self.params['vid'])])

class VLANHeaderDouble(VLANHeader):
    """A double tagged VLAN header."""

    def __init__(self, **headerParams):
        self.params = {}
        self.params['pcp'] = [0,0]
        self.params['vid'] = [1,1]
        super().__init__(**headerParams)
        if (any([pcp < 0 or pcp > 7 for pcp in self.params['pcp']]) or
            any([vid < 0 or vid > 4095 for vid in self.params['vid']]) or
            len(self.params['pcp']) % 2 != 0 or len(self.params['vid']) % 2 != 0): #double tagged vlan only accepts pcp and vid lists which are of even length
            raise ValueError("Invalid VLAN Parameters")
        self.content: Packet = Dot1Q(prio=self.params['pcp'][self.currentIndex],
                                     vlan=self.params['vid'][self.currentIndex]) / Dot1Q(prio=self.params['pcp'][self.currentIndex+1],
                                                                                         vlan=self.params['vid'][self.currentIndex+1])
    
    def nextHeader(self):
        self.currentIndex += 2
        self.content: Packet = Dot1Q(prio=self.params['pcp'][self.currentIndex%len(self.params['pcp'])],
                                     vlan=self.params['vid'][self.currentIndex%len(self.params['vid'])]) / Dot1Q(prio=self.params['pcp'][(self.currentIndex+1)%len(self.params['pcp'])],
                                                                                                            vlan=self.params['vid'][(self.currentIndex+1)%len(self.params['vid'])])
        

class MPLSHeader(Layer2Header):
    """A MPLS header."""
    def __init__(self, **headerParams):
        self.params = {}
        self.params['label'] = [3]
        self.params['qos'] = [0]
        self.params['ttl'] = [0]
        super().__init__(**headerParams)
        for key in self.params.keys():
            if key != 'label' and key != 'qos' and key != 'ttl':
                raise ValueError("Invalid MPLS params")
        if (any([label > 2**20-1 or label < 0 for label in self.params['label']]) or
            any([qos > 7 or qos < 0 for qos in self.params['qos']]) or
            any([ttl > 255 or ttl < 0 for ttl in self.params['ttl']])):
            raise ValueError("Invalid MPLS params")
        
        self.content = MPLS(label=self.params["label"][self.currentIndex],
                            cos=self.params["qos"][self.currentIndex],
                            ttl=self.params["ttl"][self.currentIndex])
    
    def nextHeader(self):
        super().nextHeader()
        self.content = MPLS(label=self.params["label"][self.currentIndex%len(self.params["label"])],
                            cos=self.params["qos"][self.currentIndex%len(self.params["qos"])],
                            ttl=self.params["ttl"][self.currentIndex%len(self.params["ttl"])])


class Ipv4Header(Layer3Header):
    """An IPv4 header."""

    def __init__(self, **headerParams):
        self.params = {}
        self.params['srcIP'] = ["127.0.0.1"]
        self.params['dstIP'] = ["127.0.0.2"]
        self.params['protocol'] = None
        super().__init__(**headerParams)
        try:
            for srcIP in self.params['srcIP']:
                IPv4Address(srcIP) 
            for dstIP in self.params['dstIP']:
                IPv4Address(dstIP)
        except:
            raise ValueError("Invalid IPv4 address(es)")
        if self.params['protocol'] != None:
            if any([prot < 0 or prot > 255 for prot in self.params['protocol']]):
                raise ValueError("Invalid Ip protocol number")
            else:
                self.content: Packet = IP(src=self.params['srcIP'][self.currentIndex],
                                   dst=self.params['dstIP'][self.currentIndex],
                                   proto=self.params['protocol'][self.currentIndex])
        else:
            self.content: Packet = IP(src=self.params['srcIP'][self.currentIndex],
                                   dst=self.params['dstIP'][self.currentIndex])
    
    def nextHeader(self):
        super().nextHeader()
        if self.params['protocol'] != None:
            self.content: Packet = IP(src=self.params['srcIP'][self.currentIndex%len(self.params['srcIP'])],
                                    dst=self.params['dstIP'][self.currentIndex%len(self.params['dstIP'])],
                                    proto=self.params['protocol'][self.currentIndex%len(self.params['protocol'])])
        else:
            self.content: Packet = IP(src=self.params['srcIP'][self.currentIndex%len(self.params['srcIP'])],
                                    dst=self.params['dstIP'][self.currentIndex%len(self.params['dstIP'])])


class Ipv6Header(Layer3Header):
    """An IPv6 header."""

    def __init__(self, **headerParams):
        self.params = {}
        self.params['srcIP'] = ["2001:0db8:85a3:0000:0000:8a2e:0370:7334"]
        self.params['dstIP'] = ["2001:0ab8:85a1:0000:0000:8a2a:037d:7224"]
        self.params['protocol'] = None
        super().__init__(**headerParams)
        try:
            for srcIP in self.params['srcIP']:
                IPv6Address(srcIP) 
            for dstIP in self.params['dstIP']:
                IPv6Address(dstIP)
        except:
            raise ValueError("Invalid IPv6 address(es)")

        if self.params['protocol'] != None:
            if any([prot < 0 or prot > 255 for prot in self.params['protocol']]):
                raise ValueError("Invalid Ip protocol number")
            else:
                self.content: Packet = IPv6(src=self.params['srcIP'][self.currentIndex],
                                   dst=self.params['dstIP'][self.currentIndex],
                                   proto=self.params['protocol'][self.currentIndex])
        else:
            self.content: Packet = IPv6(src=self.params['srcIP'][self.currentIndex],
                                   dst=self.params['dstIP'][self.currentIndex])
    
    def nextHeader(self):
        super().nextHeader()
        if self.params['protocol'] != None:
            self.content: Packet = IPv6(src=self.params['srcIP'][self.currentIndex%len(self.params['srcIP'])],
                                    dst=self.params['dstIP'][self.currentIndex%len(self.params['dstIP'])],
                                    proto=self.params['protocol'][self.currentIndex%len(self.params['protocol'])])
        else:
            self.content: Packet = IPv6(src=self.params['srcIP'][self.currentIndex%len(self.params['srcIP'])],
                                    dst=self.params['dstIP'][self.currentIndex%len(self.params['dstIP'])])


class GTPHeader(Layer4Header):

    def __init__(self, **headerParams):
        self.params = {}
        self.params['messageType'] = [0]
        self.params['teid'] = [0]
        super().__init__(**headerParams)
        for key in self.params.keys():
            if key != 'messageType' and key != 'teid':
                raise ValueError("Invalid GTP parameters")
        if (any(mt < 0 or mt > 255 for mt in self.params['messageType']) or
            any([teid < 0 or teid >= 2**32 for teid in self.params['teid']])):
            raise ValueError("Invalid GTP parameters")

class GTPv1Header(GTPHeader):
    """A GTPv1 header."""
    def __init__(self, **headerParams):
        super().__init__(**headerParams)
        self.content = GTPv1(gtp_type=self.params["messageType"][self.currentIndex],
                              teid=self.params["teid"][self.currentIndex])
    
    def nextHeader(self):
        super().nextHeader()
        self.content = GTPv1(gtp_type=self.params["messageType"][self.currentIndex%len(self.params['messageType'])],
                              teid=self.params["teid"][self.currentIndex%len(self.params['teid'])])


class GTPv2Header(GTPHeader):
    """A GTPv2 header."""
    
    def __init__(self, **headerParams):
        super().__init__(**headerParams)
        self.content = GTPv2(gtp_type=self.params["messageType"][self.currentIndex],
                              teid=self.params["teid"][self.currentIndex])
    
    def nextHeader(self):
        super().nextHeader()
        self.content = GTPv2(gtp_type=self.params["messageType"][self.currentIndex%len(self.params['messageType'])],
                              teid=self.params["teid"][self.currentIndex%len(self.params['teid'])])




class TransportHeader(Layer4Header):
    """An abstract class for a transport packets[len(packets)-1].content header."""
    
    def __init__(self, **headerParams):
        super().__init__(**headerParams)
        for key in self.params.keys():
            if key != 'srcPort' and key != 'dstPort':
                raise ValueError("Invalid transport header parameters")
        if (any([srcPort < 0 or srcPort > 65535 for srcPort in self.params['srcPort']]) or
            any([dstPort < 0 or dstPort > 65535 for dstPort in self.params['dstPort']])):
            raise ValueError("Invalid transport header parameters")


class TCPHeader(TransportHeader):
    """A TCP header."""
    def __init__(self, **headerParams):
        self.params = {}
        self.params['srcPort'] = [20]
        self.params['dstPort'] = [80]
        super().__init__(**headerParams)
        self.content: Packet = TCP(sport=self.params['srcPort'][self.currentIndex],
                                   dport=self.params['dstPort'][self.currentIndex])
    
    def nextHeader(self):
        super().nextHeader()
        self.content: Packet = TCP(sport=self.params['srcPort'][self.currentIndex%len(self.params['srcPort'])],
                                   dport=self.params['dstPort'][self.currentIndex%len(self.params['dstPort'])])


class UDPHeader(TransportHeader):
    """A UDP header."""

    def __init__(self, **headerParams):
        self.params = {}
        self.params['srcPort'] = [53]
        self.params['dstPort'] = [53]
        super().__init__(**headerParams)
        self.content: Packet = UDP(sport=self.params['srcPort'][self.currentIndex],
                                   dport=self.params['dstPort'][self.currentIndex])
    
    def nextHeader(self):
        super().nextHeader()
        self.content: Packet = UDP(sport=self.params['srcPort'][self.currentIndex%len(self.params['srcPort'])],
                                   dport=self.params['dstPort'][self.currentIndex%len(self.params['dstPort'])])


class ECPRIHeader(Layer2Header,Layer4Header):
    """A eCPRI header."""

    def __init__(self, **headerParams):
        self.params = {}
        self.params['revision'] = [1]
        self.params['c'] = [0]
        self.params['messageType'] = [0]
        super().__init__(**headerParams)
        for key in self.params.keys():
            if key != 'revision' and key != 'c' and key != 'messageType':
                raise ValueError("Invalid eCPRI parameters.")
        if (any([rev < 0 or rev > 15 for rev in self.params['revision']]) or
            any([c < 0 or c > 1 for c in self.params['c']]) or
            any([mt < 0 or mt > 255 for mt in self.params['messageType']])):
            raise ValueError("Invalid eCPRI parameters.")
        self.content: Packet = ECPRI(revision=self.params['revision'][self.currentIndex],
                                    c=self.params['c'][self.currentIndex],
                                    messageType=self.params['messageType'][self.currentIndex])

    def nextHeader(self):
        super().nextHeader()
        self.content: Packet = ECPRI(revision=self.params['revision'][self.currentIndex%len(self.params['revision'])],
                                    c=self.params['c'][self.currentIndex%len(self.params['c'])],
                                    messageType=self.params['messageType'][self.currentIndex%len(self.params['messageType'])])

class RoEHeader(Layer2Header):
    """A RoE Header"""
    def __init__(self, **headerParams):
        self.params = {}
        self.params['subType'] = [0]
        self.params['flowID'] = [255]
        self.params['orderingInfo'] = [1]
        super().__init__(**headerParams)
        for key in self.params.keys():
            if key != 'subType' and key != 'flowID' and key != 'orderingInfo':
                raise ValueError("Invalid RoE parameters.")
        if (any([st < 0 or st > 255 for st in self.params['subType']]) or
            any([fid < 0 or fid > 255 for fid in self.params['flowID']]) or
            any([ordinfo < 0 or ordinfo >= 2**32 for ordinfo in self.params['orderingInfo']])):
            raise ValueError("Invalid eCPRI parameters.")
        self.content: Packet = RoE(pckType=self.params['subType'][self.currentIndex],
                                   flowID=self.params['flowID'][self.currentIndex],
                                   orderingInfo=self.params['orderingInfo'][self.currentIndex])
    
    def nextHeader(self):
        super().nextHeader()
        self.content: Packet = RoE(pckType=self.params['subType'][self.currentIndex%len(self.params['subType'])],
                                   flowID=self.params['flowID'][self.currentIndex%len(self.params['flowID'])],
                                   orderingInfo=self.params['orderingInfo'][self.currentIndex%len(self.params['orderingInfo'])])




class Layer():
    def __init__(self):
        pass


class Layer2(Layer):
    """A layer 2 frame consisting of a combination of Ethernet, VLAN, MPLS, RoE and eCPRI headers"""
    
    def __init__(self, headers: list[Layer2Header]):
        """Accept a list of layer 2 headers and combines them into a Layer2 object if given a valid header list."""
        if len(headers) == 0 or len(headers) > 3:
            raise ValueError("Invalid layer 2 header list")
        validHeaders = False
        if len(headers) == 1:
            validHeaders = isinstance(headers[0],EthernetHeader)
        if len(headers) == 2:
            validHeaders = (all([isinstance(headers[0],EthernetHeader), isinstance(headers[1],VLANHeader)]) or
                            all([isinstance(headers[0],EthernetHeader), isinstance(headers[1],MPLSHeader)]) or
                            all([isinstance(headers[0],EthernetHeader), isinstance(headers[1],RoEHeader)]) or
                            all([isinstance(headers[0],EthernetHeader), isinstance(headers[1],ECPRIHeader)]))
        if len(headers) == 3:
            validHeaders = (all([isinstance(headers[0],EthernetHeader), isinstance(headers[1],VLANHeader), isinstance(headers[2],MPLSHeader)]) or
                            all([isinstance(headers[0],EthernetHeader), isinstance(headers[1],VLANHeader), isinstance(headers[2],ECPRIHeader)]) or
                            all([isinstance(headers[0],EthernetHeader), isinstance(headers[1],VLANHeader), isinstance(headers[2],RoEHeader)]))
        if not validHeaders:
            raise ValueError("Invalid layer 2 header list")
        self.headers = headers
    
    @classmethod
    def default(cls):
        """create default layer 2 i.e. ethernet()"""
        return cls([EthernetHeader()])

    @classmethod
    def autofillFromHeader(cls, header: Layer2Header):
        """create a layer 2 object from the highest level header e.g. mpls --> ethernet(mpls())"""
        if not isinstance(header,Layer2Header):
            raise TypeError("Can only autofill from layer 2 headers")
        if isinstance(header, EthernetHeader):
            return cls.default()
        else:
            return cls([EthernetHeader(),header])


class Layer3(Layer):
    """A layer 3 frame consisting of either an IPv4 or IPv6 header"""
    
    def __init__(self, headers: list[Layer3Header]):
        if len(headers) != 1:
            raise ValueError("Invalid layer 3 header list")
        if not isinstance(headers[0], Layer3Header):
            raise ValueError("Invalid layer 3 header list")
        self.headers = headers
    
    @classmethod
    def default(cls):
        """create default layer 3 i.e. ipv4()"""
        return cls([Ipv4Header()])
    
    @classmethod
    def autofillFromHeader(cls, header: Layer3Header):
        """create a layer 3 object from a layer 3 header"""
        return cls([header])
    
    
class Layer4(Layer):
    """A layer 4 frame consisting of a combination of UDP, TCP, GTP and eCPRI headers"""
    
    def __init__(self, headers: list[Layer4Header]):
        if len(headers) == 0 or len(headers) > 2:
            raise ValueError("Invalid layer 4 header list")
        validHeaders = False
        if len(headers) == 1:
            validHeaders = (isinstance(headers[0],TCPHeader) or
                            isinstance(headers[0],UDPHeader))
        if len(headers) == 2:
            validHeaders = (all([isinstance(headers[0],UDPHeader), isinstance(headers[1],GTPv1Header)]) or
                            all([isinstance(headers[0],UDPHeader), isinstance(headers[1],GTPv2Header)]) or
                            all([isinstance(headers[0],UDPHeader), isinstance(headers[1],ECPRIHeader)]) or
                            all([isinstance(headers[0],TCPHeader), isinstance(headers[1],GTPv2Header)]))
        if not validHeaders:
            raise ValueError("Invalid layer 4 header list")
        self.headers = headers
    
    @classmethod
    def default(cls):
        """create default layer 4 i.e. tcp()"""
        return cls([TCPHeader()])

    @classmethod
    def autofillFromHeader(cls, header: Layer4Header):
        """create a layer 4 object from the highest level header e.g. gtpv2 --> udp(gtpv2())"""
        if not isinstance(header,Layer4Header):
            raise TypeError("Can only autofill from layer 4 headers")
        if isinstance(header, TCPHeader):
            return cls.default()
        elif isinstance(header, UDPHeader):
            return cls([header])
        else:
            return cls([UDPHeader(),header])

class HeaderFrame():
    """An entire packet header frame."""

    def __init__(self, layers: list[Layer]):
        """take a list of layers and creates a headerframe object if the list of layers is valid"""
        if len(layers) == 0 or len(layers) > 3:
            raise ValueError("Invalid Frame layer list")
        validLayers = False
        if len(layers) == 1:
            validLayers = isinstance(layers[0],Layer2)
        if len(layers) == 2:
            validLayers = isinstance(layers[0],Layer2) and isinstance(layers[1],Layer3)
        if len(layers) == 3:
            validLayers = all([isinstance(layers[0],Layer2),isinstance(layers[1],Layer3),isinstance(layers[2],Layer4)])
        if not validLayers:
            raise ValueError("invalid layer order")
        self.headers: list[Header] = []
        for layer in layers:
            self.headers += layer.headers
    
    @classmethod
    def autofillFromLayer(cls, layer: Layer):
        """create a headerframe from one layer by using default values for those not specified"""
        if isinstance(layer,Layer2):
            return cls([layer])
        elif isinstance(layer,Layer3):
            return cls([Layer2.default(),layer])
        elif isinstance(layer,Layer4):
            return cls([Layer2.default(),Layer3.default(),layer])
        
    @classmethod
    def autofillFromHeader(cls, header: Header):
        """create a valid headerframe object from a single header choice, using ethernet, ipv4 and udp to encapsulate the header choice if necessary"""
        if isinstance(header, Layer2Header):
            layer = Layer2.autofillFromHeader(header)
        elif isinstance(header, Layer3Header):
            layer = Layer3.autofillFromHeader(header)
        elif isinstance(header, Layer4Header):
            layer = Layer4.autofillFromHeader(header)
        return cls.autofillFromLayer(layer)
    
    @classmethod
    def fromHeaderList(cls, headerChoices: list[Header]):
        """create a headerframe object from a valid list of the headers it should contain"""
        headers = [[],[],[]]
        index = 0
        prevIndex = 0
        for currentHeader in headerChoices:
            prevIndex = index
            index = currentHeader.checkLayer()-2
            #check that header are given in a consecutive layer order with special cases for eCPRI
            if (index == -5 and prevIndex == 0):
                index = 0
            elif (index == -5 and prevIndex == 2):
                index = 2
            elif index < prevIndex:
                raise ValueError("Invalid list of headers.")
            headers[index].append(currentHeader)
        layer2 = Layer2(headers[0])
        layer3 = None
        layer4 = None
        if len(headers[1]) > 0:
            layer3 = Layer3(headers[1])
        if len(headers[2]) > 0:
            layer4  = Layer4(headers[2])
        if layer3 == None and layer4 != None:
            raise ValueError("Invalid list of headers given")
        if layer3 == None:
            return cls([layer2])
        elif layer4 == None:
            return cls([layer2,layer3])
        else:
            return cls([layer2,layer3,layer4])
    
    def nextHeaders(self):
        for header in self.headers:
            header.nextHeader()
        
        
        


class PayloadGenerator():
    """abstract payload generator class"""
    def __init__(self):
        pass

    def nextPayload(self):
        pass


class PredefinedPayloadGenerator(PayloadGenerator):
    """A class which generates the bytes of payloads based on the configurations specified in the contructor parameters."""
    def __init__(self, initialFill: int=0, initialSize: int=64,
                randomFills: bool=False, fillStep: int =0,
                randomSizes: bool=False, sizeStep: int=0,
                minSize: int=32, maxSize: int=128):
        
        self.randomFills = randomFills if randomFills != None else False
        self.fillStep = fillStep if fillStep != None else 0
        self.randomSizes = randomSizes if randomSizes != None else False
        self.sizeStep = sizeStep if sizeStep != None else 0
        self.size = initialSize if initialSize != None else 64
        self.minSize = minSize if minSize != None else 32
        self.maxSize = maxSize if maxSize != None else 128
        self.fillAsInt = initialFill if initialFill != None else 0
        self.validateStreamInput()
        self.fill = self.fillAsInt.to_bytes(self.size,'big')
    
    def validateStreamInput(self):
        """check for any invalid configuration combinations or values"""
        if any([not isinstance(param,int) for param in [self.fillAsInt,self.size,self.fillStep,self.sizeStep,self.maxSize,self.minSize]]) or not isinstance(self.randomFills,bool) or not isinstance(self.randomSizes,bool):
            raise TypeError
        if abs(self.fillStep) > 2**(8*self.minSize)-1:
            raise ValueError("fill step must be less than the maximum possible fill value 2^(8*initialSize)-1")
        if self.fillAsInt < 0:
            raise ValueError("initial fill must be greater than 0")
        if self.randomFills and self.fillStep != 0:
            raise ValueError("Payload fill cannot be both randomized and incrementing/decremnting")
        if self.randomSizes and self.sizeStep != 0:
            raise ValueError("Payload size cannot be both randomized and incrementing/decremnting")
        if self.minSize < 1 or self.maxSize < 1: 
            raise ValueError("minPayloadSize and maxPayloadSize must be >= 1 ")
        if self.maxSize < self.maxSize or self.maxSize > self.maxSize:
            raise ValueError("Initial payload size must be in the given size range")
        if abs(self.sizeStep) > self.maxSize - self.minSize:
            raise ValueError("Payload size step must be smaller than the payload size range (maxPayloadSize - minPayloadSize)")
        if self.size < 1:
            raise ValueError("Payload size must be at least one byte")
        if self.fillAsInt > 2**(8*self.size)-1:
            raise ValueError("Payload fill value must be representable by payload byte size")
    
    def incrementFill(self):
        """increase the numerical value of the payload by the amount specified as fillStep"""
        self.fillAsInt = (self.fillAsInt + self.fillStep) % 2**(8*self.minSize)
        self.fill = int(self.fillAsInt).to_bytes(self.size,'big')
        
    
    def decrementFill(self):
        """decrease the numerical value of the payload by the amount specified as fillStep"""
        decrement = abs(self.fillStep)
        if self.fillAsInt - decrement < 0:
            self.fillAsInt = 2**(8*self.minSize) + self.fillAsInt - decrement
        else:
            self.fillAsInt = self.fillAsInt - decrement
        self.fill = int(self.fillAsInt).to_bytes(self.size,'big')
    
    def randomizeFill(self):
        """choose a new random number for the payload fill value"""
        self.fillAsInt = randint(0,2**(8*self.minSize)-1)
        self.fill = int(self.fillAsInt).to_bytes(self.size,'big')
    
    def incrementSize(self):
        """increase the byte size of the payload by the amount specified as sizeStep"""
        if self.size + self.sizeStep > self.maxSize:

            self.size = self.minSize + (self.size + self.sizeStep) % (self.maxSize + 1)
        else:
            self.size = self.size + self.sizeStep
        self.fill = self.fillAsInt.to_bytes(self.size,'big')
    
    def decrementSize(self):
        """decrease the byte size of the payload by the amount specified as sizeStep"""
        decrement = abs(self.sizeStep)
        if self.size - decrement < self.minSize:
            self.size = self.maxSize - (self.minSize - (self.size - decrement))+1
        else:
            self.size = self.size - decrement
        self.fill = self.fillAsInt.to_bytes(self.size,'big')
    
    def randomizeSize(self):
        """choose a random size in the range (minSize,maxSize) as the new byte size for the payload"""
        self.size = randint(self.minSize,self.maxSize)
        self.fill = self.fillAsInt.to_bytes(self.size,'big')
    
    def nextPayload(self):
        """generate the next payload based on payloadGenerator configurations"""
        if self.sizeStep > 0:
            self.incrementSize()
        elif self.sizeStep < 0:
            self.decrementSize()
        elif self.randomSizes:
            self.randomizeSize()
        if self.fillStep > 0:
            self.incrementFill()
        elif self.fillStep < 0:
            self.decrementFill()
        elif self.randomFills:
            self.randomizeFill()


class UserPayloadGenerator(PayloadGenerator):

    def __init__(self, byteStrings: list[str]):
        """validate input strings and initialise the first payload"""
        for byteString in byteStrings:
            self.validateByteString(byteString)
        self.byteStrings = byteStrings
        self.currentIndex = 0 
        self.fill = self.byteStringToFill(byteStrings[0])

    @staticmethod
    def validateByteString(byteString: str):
        """check that a string contains a valid binary or hex byte representation prefixed with 0x or 0b"""
        if not (fullmatch(r'(0b([01]{8})+)?',byteString) or fullmatch(r'(0x([0-9a-fA-f]{2})+)?',byteString)):
            raise ValueError("please provide all payload values as zero or more valid binary or hex byte \n e.g. '0b01001100' or '0x1fa5'")
        else: 
            return True
    
    @staticmethod
    def byteStringToFill(byteString):
        """convert input string into actual bytes"""
        if byteString[0:2] == "0b":
            numBytes = int((len(byteString) - 2) / 8)
            return int(byteString,2).to_bytes(numBytes,'big')
        elif byteString[0:2] == "0x":
            numBytes = int((len(byteString) - 2) / 2)
            return int(byteString,16).to_bytes(numBytes,'big')
        else:
            return ""
    
    def nextPayload(self):
        """change payload to the next in the list."""
        self.currentIndex = (self.currentIndex + 1) % len(self.byteStrings)
        self.fill = self.byteStringToFill(self.byteStrings[self.currentIndex])




class StreamPacket():
    """An individual network packet of any type."""
    
    def __init__(self, headerFrame: HeaderFrame, payload: bytes):
        """construct bytes of payloads from input options"""
        self.payload = payload
        self.headers: list[Packet] = headerFrame.headers
        self.content: Packet = self.headers[0].content
        for header in self.headers[1:]:
            self.content = self.content / header.content
        self.content = self.content / self.payload
        self.size = len(self.content)
    

        

class Stream():
    """A record of network packet traffic for one packet type."""
    
    def __init__(self, packets: list[StreamPacket]):
        """save list of StreamPacket objects"""
        self.packets: list[StreamPacket] = packets


class PktCountBasedIPGStream(Stream):
    """A stream where the size is specified by number of packets and the packet timing is specified by inter-packet gap."""
    def __init__(self, headerFrame: HeaderFrame, payload: PayloadGenerator, aveIPG: float, IPGRange: float,
                numPackets: int=100, timeOffset: float=0):
        if numPackets < 1:
            raise ValueError("stream must have at least one packet")
        if IPGRange/2 > aveIPG:
            raise ValueError("IPGRange must not span into negative numbers")
        if aveIPG == None:
            aveIPG = 5
        if IPGRange == None:
            IPGRange = 1
        packets: list[StreamPacket] = []
        timeStamp = timeOffset
        for i in range(numPackets):
            newPacket =  StreamPacket(headerFrame,payload.fill)
            headerFrame.nextHeaders()
            payload.nextPayload()
            newPacket.content.time = timeStamp
            packets.append(newPacket)
            ipg = normal(aveIPG,IPGRange/6.75)
            if ipg <= 0:
                ipg = 0.000001
            timeStamp += ipg
        super().__init__(packets)
                


class TimeBasedIPGStream(Stream):
    """A stream where the size is specified by total time in seconds and the packet timing is specified by inter-packet gap."""
    def __init__(self, headerFrame: HeaderFrame, payload: PayloadGenerator, aveIPG: float, IPGRange: float,
                totalStreamTime: int=1000, timeOffset: float=0):
        if totalStreamTime < 0:
            raise ValueError("totalStreamTime must be >= 0")
        if IPGRange/2 > aveIPG:
            raise ValueError("IPGRange must not span into negative numbers")
        packets: list[StreamPacket] = []
        timeStamp = timeOffset
        timeLeft = True
        while timeLeft:
            newPacket =  StreamPacket(headerFrame,payload.fill)
            headerFrame.nextHeaders()
            payload.nextPayload()
            newPacket.content.time = timeStamp
            packets.append(newPacket)
            ipg = normal(aveIPG,IPGRange/6.75)
            if ipg <= 0:
                ipg = 0.000001
            timeStamp += ipg
            if timeStamp > timeOffset + totalStreamTime:
                timeLeft = False
        super().__init__(packets)
            
    
class PktCountBasedPktRateStream(Stream):
    """A stream where the size is specified by number of packets and the packet timing is specified by packet-rate."""
    def __init__(self, headerFrame: HeaderFrame, payload: PayloadGenerator, packetsPerSecond: float, 
                numPackets: int=100, timeOffset: float=0):
        if numPackets < 1:
            raise ValueError("stream must have at least one packet")
        packets: list[StreamPacket] = []
        ipg = 1/packetsPerSecond
        timeStamp = timeOffset
        for i in range(numPackets):
            newPacket =  StreamPacket(headerFrame,payload.fill)
            headerFrame.nextHeaders()
            payload.nextPayload()
            newPacket.content.time = timeStamp
            packets.append(newPacket)
            timeStamp += ipg
        super().__init__(packets)

        
class TimeBasedPktRateStream(Stream):
    """A stream where the size is specified by total time in seconds and the packet timing is specified by packet-rate."""
    def __init__(self, headerFrame: HeaderFrame, payload: PayloadGenerator, packetsPerSecond: float, 
                totalStreamTime: int=10000, timeOffset: float=0):
        if totalStreamTime < 0:
            raise ValueError("totalStreamTime must be >= 0")
        packets: list[StreamPacket] = []
        timeStamp = timeOffset
        ipg = 1/packetsPerSecond    
        timeLeft = True
        while timeLeft:
            newPacket =  StreamPacket(headerFrame,payload.fill)
            headerFrame.nextHeaders
            payload.nextPayload()
            newPacket.content.time = timeStamp
            packets.append(newPacket)
            timeStamp += ipg
            if timeStamp > timeOffset + totalStreamTime:
                timeLeft = False
        super().__init__(packets)


class ByteCountBasedByteRateStream(Stream):
    """A stream where the size is specified by number of bytes and the packet timing is specified by byte-rate."""
    def __init__(self, headerFrame: HeaderFrame, payload: PayloadGenerator, bytesPerSecond: float, 
                 numBytes: int = 10000, fillOutWithPadding: bool=False, timeOffset: float=0):
        #if fillOutWithPadding is set as True, padding will be added to the end of the last packet in the stream
        #in order to fill the stream size out to the desired number of bytes. Otherwise, the actual stream size may be less 
        #than the specified numBytes.
        if fillOutWithPadding:
            warn("payload of last packet may be inconsistent with payload settings \n because fillOutWithPadding is set to True")
        else:
            warn("the actual number of bytes in the stream may be slightly less than \n the set numBytes because fillOutWithPadding is set to False")
        newPacket =  StreamPacket(headerFrame,payload.fill)
        if numBytes < newPacket.size:
            raise ValueError("numBytes must be at least the large enough to hold the first packet.")
        packets: list[StreamPacket] = []
        byteGap = 1/bytesPerSecond
        timeStamp = timeOffset
        streamSize = 0
        while streamSize + newPacket.size <= numBytes:
            newPacket.content.time = timeStamp
            streamSize += newPacket.size
            packets.append(newPacket)
            headerFrame.nextHeaders()
            payload.nextPayload()
            newPacket = StreamPacket(headerFrame,payload.fill)
            timeStamp += byteGap * newPacket.size
        if fillOutWithPadding:
            byteDiff = numBytes - streamSize
            if byteDiff > 0:
                pad = 0
                padding = pad.to_bytes(byteDiff,'big')
                lastPacket = packets.pop()
                streamSize -= lastPacket.size
                lastPacket.content = lastPacket.content / padding
                lastPacket.size = len(lastPacket.content)
                packets.append(lastPacket)
                streamSize += lastPacket.size
        super().__init__(packets)


class TimeBasedByteRateStream(Stream):
    """A stream where the size is specified by total time in seconds and the packet timing is specified by byte-rate."""
    def __init__(self, headerFrame: HeaderFrame, payload: PayloadGenerator, bytesPerSecond: float, 
                 totalStreamTime: int = 10000, timeOffset: float=0):
        if totalStreamTime < 0:
            raise ValueError("totalStreamTime must be >= 0")
        newPacket =  StreamPacket(headerFrame,payload.fill)
        packets: list[StreamPacket] = []
        byteGap = 1/bytesPerSecond
        timeStamp = timeOffset 
        timeLeft = True
        while timeLeft:
            newPacket.content.time = timeStamp
            packets.append(newPacket)
            headerFrame.nextHeaders()
            payload.nextPayload()
            newPacket = StreamPacket(headerFrame,payload.fill)
            timeStamp += byteGap * newPacket.size
            if timeStamp > timeOffset + totalStreamTime:
                timeLeft = False
        super().__init__(packets)
        



class Session():
    """A collection of Streams representing a complete traffic session that can be saved as a pcap with sink()."""
    
    def __init__(self, streams: list[Stream], appenIds: bool):
        self.streams = streams
        id = 0
        if appenIds:
            for stream in self.streams:
                for i in range(len(stream.packets)):
                    stream.packets[i].content["IP"] = stream.packets[i].content / id.to_bytes(4)
                    id += 1
        
    
    def sink(self,fileName: str):
        allPackets = []
        for stream in self.streams:
            for packet in stream.packets:
                allPackets.append(packet.content)
        wrpcap(fileName+".pcap",allPackets)