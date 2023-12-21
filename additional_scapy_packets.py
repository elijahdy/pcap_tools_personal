from scapy.all import *

class ECPRI(Packet):
    name = "ECPRI"
    fields_desc = [BitField("revision",1,4),
                   BitField("reserved",0,3),
                   BitField("c",0,1),
                   ByteEnumField("messageType",0,{0:'IQData',
                                                   1:'bitSequence',
                                                    2:'realTimeControlData',
                                                    3:'genericDataTranfer',
                                                    4:'remoteMemoryAccess',
                                                    5:'oneWayDelayMeasurement',
                                                    6:'remoteReset',
                                                    7:'eventIndication'}),
                   ShortField("payloadSize",0)]
    
    def post_build(self, pkt: bytes, pay: bytes) -> bytes:
        if self.payloadSize == 0:
            pkt = pkt[:2] + len(pay).to_bytes(2,'big') + pay
        return pkt
bind_layers(Ether,ECPRI,type=int("0xaefe",16))
bind_layers(Dot1Q,ECPRI,type=int("0xaefe",16))




class RoE(Packet):
    name = "RoE"
    fields_desc = [ByteEnumField("pckType",0,{0:'control',
                                           252:'experimental',
                                           253:'experimental',
                                           254:'experimental',
                                           255:'experimental',
                                           17:'nativeFrequencyDomain',
                                           18:'nativePrachData',
                                           16:'nativeTimeDomain',
                                           4:'slowCmCpriData',
                                           2:'structureAgnosticData',
                                           3:'structureAwareCPRIData'}),
                   ByteField("flowID",255),
                   ShortField("length",0),
                   IntField("orderingInfo",1)]
    
    def post_build(self, pkt: bytes, pay: bytes) -> bytes:
        if self.length == 0:
            pkt = pkt[:2] + len(pay).to_bytes(2,'big') + pkt[4:8] + pay
        return pkt
bind_layers(Ether,RoE,type=int("0xfc3d",16))
bind_layers(Dot1Q,RoE,type=int("0xfc3d",16))


