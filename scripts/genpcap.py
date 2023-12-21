#!/usr/bin/python3.10
import os
from sys import path
path.append(os.path.dirname(__file__)+"/../")
print(path)
import argparse
from pcap_gen_tool import *
from helpers import xor


def parse_arguments():
    parser = argparse.ArgumentParser(description='Script to generate single stream pcaps')
    #filename
    parser.add_argument('-fn','--filename',
                        type=str,
                        required=True,
                        action='store')
    #arguments for header types
    parser.add_argument('-pt', '--packetType',
                        type=str,
                        help="Specify packet type for stream e.g. -pt udp -> Ethernet(IPv4(UDP()))",
                        required=False,
                        action='store')
    parser.add_argument('-hd', '--headers',
                        type=str,
                        help="Specify all desired packet headers in order \n e.g -hd ethernet vlan ipv4 tcp -> Ethernet(VLAN(IPv4(TCP())))",
                        required=False,
                        nargs='+')
    #arguments for ethernet header
    parser.add_argument('-secondsrc','--macSource',
                        type=str,
                        help="Specify one or more source MAC address\n e.g. -secondsrc aa:bb:cc:dd:ee:ff",
                        required=False,
                        nargs='+')
    parser.add_argument('-mdst','--macDestination',
                        type=str,
                        help="Specify one or more destination MAC address\n e.g. -mdst aa:bb:cc:dd:ee:ff",
                        required=False,
                        nargs='+')
    parser.add_argument('-et','--etherType',
                        type=int,
                        help="Specify one or more ethernet type values as a decimal number",
                        required=False,
                        nargs='+')
    #need to figure out how to make vlan work with lists of values maybe tagtype has to be constant
    #arguments for vlan header
    parser.add_argument('-vtt','--vlanTagType',
                        choices = ['single', 'double'],
                        type=str,
                        help="Specify whether the vlan header(s) are single or double tagged",
                        required=False,
                        action='store')
    parser.add_argument('-pcp', '--vlanPcp',
                        type=int,
                        help="Specify one or more vlan pcp value for each tag \n note if the vlan tag type is double then an even number of pcps must be specified",
                        required=False,
                        nargs='+')
    parser.add_argument('-vid', '--vlanVid',
                        type=int,
                        help="Specify one or more vlan vid value for each tag \n note if the vlan tag type is double then an even number of vids must be specified",
                        required=False,
                        nargs='+')
    #arguments for mpls header
    parser.add_argument('-mplbl', '--mplsLabel',
                        type=int,
                        help="Specify one or more mpls label",
                        required=False,
                        nargs='+')
    parser.add_argument('-mpqos', '--mplsQos',
                        type=int,
                        help="Specify one or more mpls qos value",
                        required=False,
                        nargs='+')
    parser.add_argument('-mpttl', '--mplsTtl',
                        type=int,
                        help="Specify one or more mpls ttl value",
                        required=False,
                        nargs='+')  
    #arguments for Ipv4 header
    parser.add_argument('-v4src', '--ipv4Source',
                        type=str,
                        help="Specify one or more source IPv4 addresses",
                        required=False,
                        nargs='+')
    parser.add_argument('-v4dst', '--ipv4Destination',
                        type=str,
                        help="Specify one or more destination IPv4 addresses",
                        required=False,
                        nargs='+')
    parser.add_argument('-v4prot', '--ipv4Protocol',
                        type=int,
                        help="Specify one or more IPv4 protocol values as decimal numbers",
                        required=False,
                        nargs='+')
    #arguments for Ipv6 header
    parser.add_argument('-v6src', '--ipv6Source',
                        type=str,
                        help="Specify one or more source IPv6 addresses",
                        required=False,
                        nargs='+')
    parser.add_argument('-v6dst', '--ipv6Destination',
                        type=str,
                        help="Specify one or more destination IPv6 addresses",
                        required=False,
                        nargs='+')
    parser.add_argument('-v6prot', '--ipv6Protocol',
                        type=int,
                        help="Specify one or more IPv6 protocol/next_header values as decimal numbers",
                        required=False,
                        nargs='+')
    #arguments for gtp header
    parser.add_argument('-gv', '--gtpVersion',
                        type=int,
                        help="Specify the gtp version",
                        required=False,
                        action = 'store')
    parser.add_argument('-gmt', '--gtpMessageType',
                        type=int,
                        help="Specify one or more GTP message types",
                        required=False,
                        nargs='+')
    parser.add_argument('-gid', '--gtpTeid',
                        type=int,
                        help="Specify one or more GTP teids",
                        required=False,
                        nargs='+')
    #arguments for TCP header
    parser.add_argument('-tsrc', '--tcpSourcePort',
                        type=int,
                        help="Specify one or more TCP source ports",
                        required=False,
                        nargs='+')
    parser.add_argument('-tdst', '--tcpDestinationPort',
                        type=int,
                        help="Specify one or more TCP destination ports",
                        required=False,
                        nargs='+')
    #arguments for UDP header
    parser.add_argument('-usrc', '--udpSourcePort',
                        type=int,
                        help="Specify one or more UDP source ports",
                        required=False,
                        nargs='+')
    parser.add_argument('-udst', '--udpDestinationPort',
                        type=int,
                        help="Specify one or more UDP destination ports",
                        required=False,
                        nargs='+')
    #arguments for eCPRI header
    parser.add_argument('-erv', '--ecpriRevision',
                        type=int,
                        help="Specify one or more eCPRI revision values",
                        required=False,
                        nargs='+') 
    parser.add_argument('-ec', '--ecpriC',
                        type=int,
                        help="Specify one or more eCPRI c values",
                        required=False,
                        nargs='+')
    parser.add_argument('-emt', '--ecpriMessageType',
                        type=int,
                        help="Specify one or more eCPRI message types",
                        required=False,
                        nargs='+')
    #arguments for RoE header
    parser.add_argument('-rst', '--roeSubType',
                        type=int,
                        help="Specify one or more RoE subtypes",
                        required=False,
                        nargs='+')
    parser.add_argument('-rid', '--roeFlowId',
                        type=int,
                        help="Specify one or more RoE flow IDs",
                        required=False,
                        nargs='+')
    parser.add_argument('-roi', '--roeOrderingInfo',
                        type=int,
                        help="Specify one or more RoE ordering info values",
                        required=False,
                        nargs='+')                    
    #arguments for data payload
    parser.add_argument('-ifl', '--initialPayloadFill',
                        type=int,
                        help='Specify the value which should fill the first data payload in the stream, this should be given as a decimal number \n e.g. -ifl 10 -> 0x0A given --initialSize == 1',
                        required=False,
                        action='store')
    parser.add_argument('-isz', '--initialPayloadSize',
                        type=int,
                        help='Specify the byte size of the first data payload in the stream \ne.g. -isz 4 -> 0x00000000 given --initialFill == 0',
                        required=False,
                        action='store')
    parser.add_argument('-rfl', '--randomizePayloadFill',
                        type=bool,
                        help='Specify as true to use a random value for the data payload of each packet',
                        required=False,
                        action='store')
    parser.add_argument('-rsz', '--randomizePayloadSize',
                        type=bool,
                        help='Specify as true to choose a random byte size for each data payload within the range (--maxPayloadSize,--minPayloadSize) which is (32,128) by default',
                        required=False,
                        action='store')
    parser.add_argument('-flstp', '--fillStep',
                        type=int,
                        help='Specify the amount which the data payload fill value should change by between each packet',
                        required=False,
                        action='store')
    parser.add_argument('-szstp', '--sizeStep',
                        type=int,
                        help='Specify the amount which the data payload size should change by between each packet',
                        required=False,
                        action='store')
    parser.add_argument('-mnsz', '--minPayloadSize',
                        type=int,
                        help='Specify the minimum byte size for each data payload',
                        required=False,
                        action='store')
    parser.add_argument('-mxsz', '--maxPayloadSize',
                        type=int,
                        help='Specify the maximum byte size for each data payload',
                        required=False,
                        action='store')
    parser.add_argument('-up', '--userPayload',
                        type=str,
                        help="Specify one or more data payloads to cycle through as bytes in binary or hex notation \n e.g. -up 0xffffffff 0b1001100101100110",
                        required=False,
                        nargs='+')
    parser.add_argument('-np', '--noPayload',
                        help='Add this flag to create packets with no data payload',
                        required=False,
                        action='store_true')
    #timing and stream size arguments
    parser.add_argument('-tst', '--totalStreamTime',
                        type=float,
                        help='Specify the amount of time in seconds that the stream should last',
                        required=False,
                        action='store')
    parser.add_argument('-pkc', '--totalPacketCount',
                        type=int,
                        help='Specify the number of packets that should be in stream',
                        required=False,
                        action='store')
    parser.add_argument('-bc', '--totalByteCount',
                        type=int,
                        help='Specify the number of bytes that should be in stream',
                        required=False,
                        action='store')
    parser.add_argument('-aipg', '--averageIpg',
                        type=float,
                        help='Specify the mean inter-packet gap in seconds',
                        required=False,
                        action='store')
    parser.add_argument('-ipgr', '--ipgRange',
                        type=float,
                        help='Specify the size of the inter-packet gap range about the mean in seconds',
                        required=False,
                        action='store')
    parser.add_argument('-pr', '--packetRate',
                        type=float,
                        help='Specify the packet-rate of the stream in packets per second',
                        required=False,
                        action='store')
    parser.add_argument('-br', '--byteRate',
                        type=float,
                        help='Specify the byte-rate of the stream in bytes per second',
                        required=False,
                        action='store')
    parser.add_argument('-fwp', '--fillWithPadding',
                        help='Add this flag to add padding to the last packet in order to fill it out to the exact byte count specified',
                        required=False,
                        action='store_true')
    args = parser.parse_args()
    return args

def errorCheckArgs(args, frameInput):
    if not xor([args.totalStreamTime != None, args.totalPacketCount != None, args.totalByteCount != None]):
        raise ValueError("Please specify exactly one metric of stream size \n i.e totalStreamTime, totalPacketCount or totalByteCount")
    if not xor([args.averageIpg != None and args.ipgRange != None, args.packetRate != None, args.byteRate != None]):
        raise ValueError("Specify either --ipgRange and --averageIpg, --packetRate or --byteRate")
    if (args.byteRate != None and args.totalPacketCount != None) or (args.totalByteCount != None and args.packetRate != None):
        raise ValueError("Please give all stream settings in terseconds of packets or bytes, not a combination of the two")
    if any([args.initialPayloadFill != None, args.initialPayloadSize != None, 
            args.randomizePayloadFill != None, args.randomizePayloadSize != None,
            args.fillStep != None, args.sizeStep != None, args.minPayloadSize != None,
            args.maxPayloadSize != None]) and args.userPayload != None:
        raise ValueError("Specify user defined payload(s), or predefined payload options but not both.")
    if args.vlanTagType == 'double' and (len(args.vlanPcp) % 2 != 0 or len(args.vlanVid) % 2 != 0):
        raise ValueError("please give even number of pcps and vids for double tagged vlan")
    acceptedHeaders = ['ethernet','vlan','mpls','ecpri','roe','ipv4','ipv6','tcp','udp','gtp']
    if frameInput == 'headers':
        headers = [head.lower() for head in args.headers]
        for header in headers:
            if not header in acceptedHeaders:
                raise ValueError("invalid header name given")
        if (args.vlanTagType != None or args.vlanPcp != None or args.vlanVid != None) and not 'vlan' in headers:
            raise ValueError("VLAN configurations were added for a frame with no VLAN header")
        if (args.mplsLabel != None or args.mplsTtl != None) and not 'mpls' in headers:
            raise ValueError("MPLS configurations were added for a frame with no MPLS header")
        if (args.ecpriRevision != None or args.ecpriC != None or args.ecpriMessageType != None) and not 'ecpri' in headers:
            raise ValueError("eCPRI configurations were added for a frame with no eCPRI header")
        if (args.roeSubType != None or args.roeFlowId != None or args.roeOrderingInfo != None) and not 'roe' in headers:
            raise ValueError("RoE configurations were added for a frame with no RoE header")
        if (args.ipv4Destination != None or args.ipv4Source != None) and not 'ipv4' in headers:
            raise ValueError("IPv4 configurations were added for a frame with no IPv4 header")
        if (args.ipv6Destination != None or args.ipv6Source != None) and not 'ipv6' in headers:
            raise ValueError("IPv6 configurations were added for a frame with no IPv6 header")
        if (args.tcpSourcePort != None or args.tcpDestinationPort != None) and not 'tcp' in headers:
            raise ValueError("TCP configurations were added for a frame with no TCP header")
        if (args.udpSourcePort != None or args.udpDestinationPort != None) and not 'udp' in headers:
            raise ValueError("UDP configurations were added for a frame with no UDP header")
        if (args.gtpVersion != None or args.gtpMessageType != None or args.gtpTeid != None) and not 'gtp' in headers:
            raise ValueError("GTP configurations were added for a frame with no GTP header")
    elif frameInput == 'packetType':
        packetType = args.packetType.lower()
        if not packetType in acceptedHeaders:
            raise ValueError("invalid packetType given")
        if (args.vlanTagType != None or args.vlanPcp != None or args.vlanVid != None) and packetType != 'vlan':
            raise ValueError("VLAN configurations were added for a frame with no VLAN header")
        if (args.mplsLabel != None or args.mplsTtl != None) and packetType != 'mpls':
            raise ValueError("MPLS configurations were added for a frame with no MPLS header")
        if (args.ecpriRevision != None or args.ecpriC != None or args.ecpriMessageType != None) and packetType != 'ecpri':
            raise ValueError("eCPRI configurations were added for a frame with no eCPRI header")
        if (args.roeSubType != None or args.roeFlowId != None or args.roeOrderingInfo != None) and packetType != 'roe':
            raise ValueError("RoE configurations were added for a frame with no RoE header")
        if (args.ipv4Destination != None or args.ipv4Source != None) and packetType != 'ipv4' and packetType != 'udp' and packetType != 'tcp' and packetType != 'gtp':
            raise ValueError("IPv4 configurations were added for a frame with no IPv4 header")
        if (args.ipv6Destination != None or args.ipv6Source != None) and packetType != 'ipv6':
            raise ValueError("IPv6 configurations were added for a frame with no IPv6 header")
        if (args.tcpSourcePort != None or args.tcpDestinationPort != None) and packetType != 'tcp':
            raise ValueError("TCP configurations were added for a frame with no TCP header")
        if (args.udpSourcePort != None or args.udpDestinationPort != None) and packetType != 'udp' and packetType != 'gtp':
            raise ValueError("UDP configurations were added for a frame with no UDP header")
        if (args.gtpVersion != None or args.gtpMessageType != None or args.gtpTeid != None) and packetType != 'gtp':
            raise ValueError("GTP configurations were added for a frame with no GTP header")

def createHeader(headerChoice, args):
    header = EthernetHeader()
    if headerChoice == 'ethernet':
        header = EthernetHeader(srcMAC=args.macSource,dstMAC=args.macDestination,type=args.etherType)
    elif headerChoice == 'vlan':
        if args.vlanTagType == 'double':
            header = VLANHeaderDouble(pcp=args.vlanPcp,vid=args.vlanVid)
        elif args.vlanTagType == 'single':
            header = VLANHeaderSingle(pcp=args.vlanPcp,vid=args.vlanVid)
        elif args.vlanTagType == None and args.vlanPcp == None and args.vlanVid == None:
            header = VLANHeaderSingle()
        else:
            raise ValueError("Please specify valid vlanTagType i.e. single or double")
    elif headerChoice == 'mpls':
        header = MPLSHeader(label=args.mplsLabel, qos=args.mplsQos, ttl=args.mplsTtl)
    elif headerChoice == 'ecpri':
        header = ECPRIHeader(revision=args.ecpriRevision,c=args.ecpriC,messageType=args.ecpriMessageType)
    elif headerChoice == 'roe':
        header = RoEHeader(subType=args.roeSubType,flowID=args.roeFlowId,orderingInfo=args.roeOrderingInfo)
    elif headerChoice == 'ipv4':
        header = Ipv4Header(srcIP=args.ipv4Source,dstIP=args.ipv4Destination,protocol=args.ipv4Protocol)
    elif headerChoice == 'ipv6':
        header = Ipv6Header(srcIP=args.ipv6Source,dstIP=args.ipv6Destination,protocol=args.ipv6Protocol)
    elif headerChoice == 'tcp':
        header = TCPHeader(srcPort=args.tcpSourcePort,dstPort=args.tcpDestinationPort)
    elif headerChoice == 'udp':
        header = UDPHeader(srcPort=args.udpSourcePort,dstPort=args.udpDestinationPort)
    else:
        if args.gtpVersion == 1:
            header = GTPv1Header(messageType=args.gtpMessageType,teid=args.gtpTeid)
        elif args.gtpVersion == 2 or args.gtpVersion == None:
            header = GTPv2Header(messageType=args.gtpMessageType,teid=args.gtpTeid)
    return header   

def genHeaderFrame(args, frameInput):
    if frameInput == 'packetType':
        headerFrame = HeaderFrame.autofillFromHeader(createHeader(args.packetType.lower(),args))
    elif frameInput == 'headers':
        headerChoices = []
        for choice in args.headers:
            headerChoices.append(createHeader(choice,args))
        headerFrame = HeaderFrame.fromHeaderList(headerChoices)
    return headerFrame

def createPayloadGen(args):
    if args.noPayload == True:
        payloadGen = UserPayloadGenerator([""])
    elif args.userPayload != None:
        payloadGen = UserPayloadGenerator(args.userPayload)
    else:
        payloadGen = PredefinedPayloadGenerator(args.initialPayloadFill,args.initialPayloadSize,
                                                args.randomizePayloadFill, args.fillStep,
                                                args.randomizePayloadSize, args.sizeStep,
                                                args.minPayloadSize, args.maxPayloadSize)
    return payloadGen

def genStream(headerFrame: HeaderFrame, payloadGen: PayloadGenerator, args):
    ipgStream = args.averageIpg != None or args.ipgRange != None
    if ipgStream and args.totalPacketCount != None:
        stream = PktCountBasedIPGStream(headerFrame, payloadGen, args.averageIpg, args.ipgRange, args.totalPacketCount)
    elif ipgStream and args.totalStreamTime != None:
        stream = TimeBasedIPGStream(headerFrame,payloadGen,args.averageIpg,args.ipgRange,args.totalStreamTime)
    elif args.packetRate != None and args.totalPacketCount != None:
        stream = PktCountBasedPktRateStream(headerFrame,payloadGen,args.packetRate,args.totalPacketCount)
    elif args.packetRate != None and args.totalStreamTime != None:
        stream = TimeBasedPktRateStream(headerFrame,payloadGen,args.packetRate,args.totalStreamTime)
    elif args.byteRate != None and args.totalByteCount != None:
        stream = ByteCountBasedByteRateStream(headerFrame,payloadGen,args.byteRate,args.totalByteCount,args.fillWithPadding)
    elif args.byteRate != None and args.totalStreamTime != None:
        stream = TimeBasedByteRateStream(headerFrame,payloadGen,args.byteRate,args.totalStreamTime)
    return stream

def run():
    args = parse_arguments()
    if args.packetType == None and args.headers == None or args.packetType != None and args.headers != None:
        raise ValueError("please specify either packetType or header(s) but not both")
    frameInput = 'headers' if args.headers != None else 'packetType'
    errorCheckArgs(args, frameInput)
    headerFrame = genHeaderFrame(args, frameInput)
    payloadGen  = createPayloadGen(args)
    stream = genStream(headerFrame, payloadGen, args)
    session = Session([stream], False)
    session.sink(args.filename)


if __name__ == "__main__":
    try:
        print("Generating pcap file ...")
        run()
        print("----------pcap complete----------")
    except ValueError as err:
        print("Invalid settings: {0}".format(err))