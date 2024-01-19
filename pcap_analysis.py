import os
from sys import path
path.append(os.path.dirname(__file__))
from scapy.all import *
from additional_scapy_packets import *
from scapy.layers.inet import TCP
from scapy.contrib.mpls import *
from scapy.contrib.gtp_v2 import GTPHeader as GTPv2
from scapy.contrib.gtp import GTPHeader as GTPv1
from scapy.layers.l2 import Dot1Q
from numpy import mean, std

class TrafficAnalyser():
        
        def __init__(self, packets):
                self.packets = packets
                self.totalPackets = len(self.packets)
                self.packetByteSizes = [len(bytes(packet)) for packet in self.packets]
                self.totalBytes = sum(self.packetByteSizes)
                self.times = [float(packet.time) for packet in self.packets]
                self.totalTime = float(self.packets[len(self.packets)-1].time) - float(self.packets[0].time)
                if self.totalPackets > 1:
                        self.packetRate = self.totalPackets/self.totalTime
                        self.byteRate = self.totalBytes/self.totalTime
                        ipgTotal = 0
                        for i in range(1,len(self.times)):
                                ipgTotal += self.times[i] - self.times[i-1]
                        self.meanIpg = ipgTotal / (len(self.times)-1)
                self.sortPacketsByProtocol()
                self.packetTypeCounts = {}
                for key in self.packetsByProtocol.keys():
                        self.packetTypeCounts[key] = len(self.packetsByProtocol[key])
        
        @classmethod
        def fromPcap(cls, filepath: str):
                packets = rdpcap(filepath)
                return cls(packets)                
        
        def sortPacketsByProtocol(self):
                #parsing of GTP does not work yet
                self.packetsByProtocol ={}
                self.packetsByProtocol['ethernet'] = [] 
                self.packetsByProtocol['vlan']  = []
                self.packetsByProtocol['mpls']  = []
                self.packetsByProtocol['roe'] = []
                self.packetsByProtocol['ecpri'] = []
                self.packetsByProtocol['ipv4'] = []
                self.packetsByProtocol['ipv6'] = []
                self.packetsByProtocol['udp'] = []
                self.packetsByProtocol['tcp'] = []
                self.packetsByProtocol['gtp'] = []
                self.packetsByProtocol['other'] = []
                for packet in self.packets:
                        if isinstance(packet.lastlayer(),Raw):
                                identityLayer = packet.lastlayer().underlayer
                        else:
                                identityLayer = packet.lastlayer()
                        print(identityLayer)
                        if isinstance(identityLayer,Ether):
                                self.packetsByProtocol['ethernet'].append(packet)
                        elif isinstance(identityLayer,Dot1Q):
                                self.packetsByProtocol['vlan'].append(packet)
                        elif isinstance(identityLayer,MPLS):
                                self.packetsByProtocol['mpls'].append(packet)
                        elif isinstance(identityLayer,RoE):
                                self.packetsByProtocol['roe'].append(packet)
                        elif isinstance(identityLayer,ECPRI):
                                self.packetsByProtocol['ecpri'].append(packet)
                        elif isinstance(identityLayer,IP):
                                self.packetsByProtocol['ipv4'].append(packet)
                        elif isinstance(identityLayer,IPv6):
                                self.packetsByProtocol['ipv6'].append(packet)
                        elif isinstance(identityLayer,UDP):
                                self.packetsByProtocol['udp'].append(packet)
                        elif isinstance(identityLayer,TCP):
                                self.packetsByProtocol['tcp'].append(packet)
                        elif isinstance(identityLayer,GTPv1) or isinstance(identityLayer,GTPv2):
                                self.packetsByProtocol['gtp'].append(packet)
                        else:
                                self.packetsByProtocol['other'].append(packet)
                        
        
        def createProtocolSpecificAnalysis(self, protocol: str):
                protocol = protocol.lower()
                packets = PacketList(self.packetsByProtocol[protocol])
                return TrafficAnalyser(packets)
        
        def summary(self):
                print("----------PCAP_SUMMARY_STATS----------")
                print("Number of Packets:",self.totalPackets)
                print("Number Of Bytes:",self.totalBytes)
                print("Total Time (s):",self.totalTime)
                print("-----Packet_Counts_by_Protocol-----")
                print(self.packetTypeCounts)
                if self.totalPackets > 1:
                        print("Mean Packet Rate (packets/s):",self.packetRate)
                        print("Mean Byte Rate (bytes/s):",self.byteRate)
                        print("Mean inter-packet gap (s):",self.meanIpg)
                        print("-----Packet_Arrival_Times_(s)-----")
                        for time in self.times:
                                print(time)
                        print("---------------------------------------")
        
        def getPacketBytes(self, packetIndex: int) -> bytes:
                packet = self.packets[packetIndex]
                print(hexdump(packet))
                return bytes(packet)
        
        def getAllPacketBytes(self) -> list[bytes]:
                allPacketBytes = [bytes(packet) for packet in self.packets]
                for packetBytes in allPacketBytes:
                        print(hexdump(packetBytes))
                return allPacketBytes


class TrafficComparison(): 

        def __init__(self, input: TrafficAnalyser, output: TrafficAnalyser):
                self.input = input
                self.output = output
        
        def summary(self):
                pass
       
       

class SizeComparison(TrafficComparison):

        def __init__(self, input: TrafficAnalyser, output: TrafficAnalyser):
                super().__init__(input,output)
                self.packetsDifference = self.input.totalPackets - self.output.totalPackets
                self.byteDifference = self.input.totalBytes - self.output.totalBytes


        def summary(self):
                print("Pcap Size Difference Stats")
                print("-----------------------")
                print("Packet Difference (|input| - |output|):",self.packetsDifference)
                print("Byte Difference (|input| - |output|):",self.byteDifference)
                print("-------------------------")


class TimeComparison(TrafficComparison):

        def __init__(self, input: TrafficAnalyser, output: TrafficAnalyser):
                super().__init__(input,output)
                self.timeDisplacements = []
                for i in range(len(self.input.times)):
                        self.timeDisplacements.append(self.output.times[i] - self.input.times[i])
                self.aveTimeDisplacement = mean(self.timeDisplacements)
                self.maxTimeDisplacement = max(self.timeDisplacements)
                self.minTimeDisplacement = min(self.timeDisplacements)
                self.timeDisplacementSD = std(self.timeDisplacements)
                self.packetsDifference = self.input.totalPackets - self.output.totalPackets
                self.byteDifference = self.input.totalBytes - self.output.totalBytes


        def summary(self):
                print("Pcap Size Difference Stats")
                print("-----------------------")
                print("Packet Difference (|input| - |output|):",self.packetsDifference)
                print("Byte Difference (|input| - |output|):",self.byteDifference)
                print("-------------------------")
                print("Packet Timing Comparison Stats")
                print("-----------------------")
                print("Average Time Displacement Between Input and Output:",self.aveTimeDisplacement)
                print("Maximum Time Displacement Between Input and Output:",self.maxTimeDisplacement)
                print("Minimum Time Displacement Between Input and Output:",self.minTimeDisplacement)
                print("Standard Deviation of Time Displacement:",self.timeDisplacementSD)
                print("Packet Timestamps in Order")
                print("---------------------")
                print("|Input|Output|")
                for i in range(len(self.input.times)):
                        print("|",self.input.times[i],"|",self.output.times[i],"|")
                print("---------------------")

class OrderedTimeComparison(TrafficComparison):
        # ordered time comparison of input and output for when the input has been generated with the pcap gen tool with the appendIDs option, 
        # this allows the packets to be reordered between input and output without losing the ability to compare the same packet in output with it's input counterpart.
        def sortByID(self, analyser: TrafficAnalyser):
                def last_4_bytes(item):
                        return bytes(item)[-4:]
                analyser.packets = sorted(analyser.packets, key=last_4_bytes)

        def __init__(self, input: TrafficAnalyser, output: TrafficAnalyser):
                super().__init__(input, output)
                self.sortByID(self.output)
                self.timeDisplacements = []
                for i in range(len(self.input.times)):
                        self.timeDisplacements.append(self.output.times[i] - self.input.times[i])
                self.aveTimeDisplacement = mean(self.timeDisplacements)
                self.maxTimeDisplacement = max(self.timeDisplacements)
                self.minTimeDisplacement = min(self.timeDisplacements)
                self.timeDisplacementSD = std(self.timeDisplacements)
        
        def summary(self):
                print("Packet Timing Comparison Stats")
                print("-----------------------")
                print("Average Time Displacement Between Input and Output:",self.aveTimeDisplacement)
                print("Maximum Time Displacement Between Input and Output:",self.maxTimeDisplacement)
                print("Minimum Time Displacement Between Input and Output:",self.minTimeDisplacement)
                print("Standard Deviation of Time Displacement:",self.timeDisplacementSD)
                print("Packet Timestamps in Order")
                print("---------------------")
                print("|Input|Output|")
                for i in range(len(self.input.times)):
                        print("|",self.input.times[i],"|",self.output.times[i],"|")
                print("---------------------")


class PacketContentComparison(TrafficComparison):

        def __init__(self, input: TrafficAnalyser, output: TrafficAnalyser):
                super().__init__(input, output)
                self.numUnmodifiedPackets = 0
                self.numModifiedPackets = 0
                self.modifiedPacketIndices = []
                for i in range(self.input.totalPackets):
                        if bytes(self.input.packets[i]) == bytes(self.output.packets[i]):
                                self.numUnmodifiedPackets += 1
                        else:
                                self.numModifiedPackets += 1
                                self.modifiedPacketIndices.append(i)
                self.modifiedPercentage = self.numUnmodifiedPackets/(self.numModifiedPackets + self.numUnmodifiedPackets)
        
        def summary(self):
                print("Modified Packet Stats")
                print("-----------------------")
                print("Number of Modified Packets:",self.numModifiedPackets)
                print("Number of Unmodified Packets:",self.numUnmodifiedPackets)
                print("Indices of Modified Packets:",self.modifiedPacketIndices)
                print("---------------------")

class PacketOrderComparison(TrafficComparison):

        def __init__(self, input: TrafficAnalyser, output: TrafficAnalyser):
                super().__init__(input, output)
                self.reorderedCount = 0
                self.reorderedPacketTimeDisplacementsDict = {}
                self.reorderedPacketDistancesDict = {}
                for i,packet in enumerate(self.output.packets):
                        id = int.from_bytes(bytes(packet)[-4:])
                        if id != i:
                                self.reorderedCount += 1
                                self.reorderedPacketTimeDisplacementsDict[id] = (self.output.times[i] - self.input.times[id])
                                self.reorderedPacketDistancesDict[id] = (abs(id-i))
                self.reorderedPacketTimeDisplacements = list(self.reorderedPacketTimeDisplacementsDict.values())
                self.reorderedPacketDistances = list(self.reorderedPacketDistancesDict.values())
                if self.reorderedCount > 0:
                        self.reorderedPercentage = (output.totalPackets/self.reorderedCount)*100
                        self.minTimeDisplacement = min(self.reorderedPacketTimeDisplacements)
                        self.maxTimeDisplacement = max(self.reorderedPacketTimeDisplacements)
                        self.avgTimeDisplacement = mean(self.reorderedPacketTimeDisplacements)
                        self.minPacketDistance = min(self.reorderedPacketDistances)
                        self.maxPacketDistance = max(self.reorderedPacketDistances)
                        self.avgPacketDistance = mean(self.reorderedPacketDistances)
                else:
                        self.reorderedPercentage = 0
                        self.minTimeDisplacement = 0
                        self.maxTimeDisplacement = 0
                        self.avgTimeDisplacement = 0
                        self.minPacketDistance = 0
                        self.maxPacketDistance = 0
                        self.avgPacketDistance = 0
        
        def summary(self):
                print("Packet Reordering Stats")
                print("-----------------------")
                print(f"number of reordered packets: {self.reorderedCount}")
                print(f"percentage of packets reordered: {self.reorderedPercentage}")
                print(f"maximum time displacement of a reordered packet: {self.maxTimeDisplacement}")
                print(f"minimum time displacement of a reordered packet: {self.minTimeDisplacement}")
                print(f"mean time displacement of a reordered packet: {self.avgTimeDisplacement}")
                print(f"maximum reorder packet distance: {self.maxPacketDistance}")
                print(f"minimum reorder packet distance: {self.minPacketDistance}")
                print(f"mean reorder packet distance: {self.avgPacketDistance}")
                print("Reorder Stats for Individual Packets")
                print("|packet ID|time diplacement|packet distance|")
                for id in sorted(list(self.reorderedPacketDistancesDict.keys())):
                        print(f"|{id}|{self.reorderedPacketTimeDisplacementsDict[id]}|{self.reorderedPacketDistances[id]}|")
                print("---------------------")