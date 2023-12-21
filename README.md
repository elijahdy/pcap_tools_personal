# genpcap Command-Line Tool
## Setup
Navigate to  the project repository and enter `pip install -e .` to activate tool. You can then use the tool with linux with `genpcap.py *flags*` or for windows navigate to scripts directory and use the command `python genpcap.py *flags*`

## Filename
Use `--filename *filename*` or `-fn *filename*` to set your desired pcap filename.

## Protocol Selection
There are two different ways to choose the protocol frame for the packets in your pcap.
###  --packetType / -pt
With this input method you select one protocol option: ethernet, vlan, mpls, roe, ecpri, ipv4, ipv6, udp, tcp or gtp to be the highest level protocol in the packet with ethernet, ipv4 and udp filling in as default lower level protocols when needed. e.g `-pt gtp` --> ethernet(ipv4(udp(gtp))).
### --header / -hd
With this input method you list each protocol in the packet starting at the lowest level i.e. ethernet. e.g. `-hd ethernet vlan ipv6` --> ethernet(vlan(ipv6)).

## Protocol Configuration
There are flags that allow you to set values that can be filtered with the SNE packet filters, check the code or use `genpcap.py --help` for more information about each of these flags. most of these flags, bar `--vlanTagType` and `--gtpVersion`, allow for input of multiple values to be iterated over throughout the stream. e.g. `-msrc aa:aa:aa:aa:aa:aa bb:bb:bb:bb:bb:bb` will alternate between these two ethernet source mac addresses throughout the pcap. You do not have to specify every configuration value for every header, default values will fill in any unspecified fields.

## Data Payload Configuration
The data payloads of the packets in the pcap can be set in one of three ways.
### Predefined Data Payload Settings
If you wish to use program generated payloads that can be incrementing/decrementing/random in size and numerical value, check `--help` to see the flags which configure the predefined payload settings.
### User Defined Data Payloads
the `--userPayload` or `-up` flag can be used to give a list of payloads in the form of binary or hex bytes that will be iterated throughout the pcap 
e.g. `-up 0x1234 0b10101010 0xffffffffffffffff` to iterate these 3 byte values as data payloads for each packet in the pcap.
### No Payload
add the flag `-np` or `--noPayload` to create packets with no data payload

## Stream Size
The size of the stream can be specified in one of three ways:
- `--totalStreamTime`/`-tst` 
- `--totalPacketCount`/`-pkc` 
- `--totalByteCount`/`-bc` <br>
 Note exactly one of these must be chosen as the stream size metric. When the total byte count is chosen, by default, the stream is filled with packets until the next packet will cause the stream to exceed the given byte count, you can add the flag `-fwp` or `--fillWithPadding` to add padding to the last packet in order to meet the specified byte count exactly. Furthermore, `--totalByteCount` can only be specified if the packet timing is given as byte-rate and `--totalPacketCount` can only be specified if the packet timing is given as the inter-packet gap or packet-rate.

## Packet Timing
The timing of the packets in the pcap can be specified in one of three ways.
### Inter-packet Gap
`--averageIpg`/`-aipg` and `--ipgRange`/`-ipgr` can be specified in order to set the average gap in seconds between packets and the size of the range that these gaps should span also in seconds. Note if this is used, the stream size cannot be given as bytes.
### Packet-Rate
If you wish for the packets to arrive at a constant rate, you can specify the packets per second with `--packetRate`/`-pr`. Note if this is specified, the stream size cannot be given as bytes.
### Byte-Rate
The timing of the packets can also be specified in bytes per second with `--byteRate`/`-br`. Note if this is specified, the stream size cannot be given as packets.

## Example
`genpcap.py -fn example -hd ethernet ipv4 -v4src 192.168.0.2 192.168.0.3 192.168.0.4 192.168.1.1 -v4dst 192.168.0.3 192.168.0.4 192.168.0.2 192.168.1.2 -isz 128 -rfl true -pkc 4 -aipg 1 -ipgr 1`

# pcap_gen_tool Source Code
There are limitations to using this tool through the command-line interface for example, A pcap file can only be made with one packet stream and it is hard to use within another program. To access the complete functionality of the tool and easily integrate pcap generation into other code, you can use the source code directly. Below I will give a brief guide on how this can be done with some examples.

## Classes
To understand how to use the code, it will be helpful to understand the class structure.
### Session
Session is the class representation of the pcap output, it contains one or more Streams that can be combined and saved as a single pcap file with the Session.sink() function. The session constructor also has an argument appendIDs. If set as True, this will append a 4 byte unique ID to the end of every packet so that packet reordering cand be detected with the pcap analysis tool. Note that the IDs will affect payload sizes and potentially checksums so if valid packets are a matter of concern this option should be set to False.
### Stream
A Stream contains a flow of network packets all with the same protocol type. A Stream can be given a time offset to delay its start within the session. there are 6 child classes of Stream each of which has different input parameters for the Stream size and the packet timing:
- PktCountBasedIPGStream: Stream size is given as total number of packets, packet timing is given by average inter-packet gap and inter-packet gap range in milliseconds.
- TimeBasedIPGStream: Stream size is given as total length in milliseconds, packet timing is given by average inter-packet gap and inter-packet gap range in milliseconds.
- PktCountBasedPktRateStream: Stream size is given as total number of packets, packet timing is given by packets per second.
- TimeBasedPktRateStream: Stream size is given as total length in milliseconds, packet timing is given by packets per second.
- ByteCountBasedByteRateStream: Stream size is given as total number of bytes and packet timing is given by bytes per second. Note that due to uncertainty in packet sizes, the desired byte count usually can't be fulfilled exactly while preserving packet content configurations. Therefore, there is a flag in the constructor of this class fillOutWithPadding, if this is set to false the stream will populate with packets up until the point where adding the next packet will make the stream exceed the specified byte size. If fillOutWithPadding is set to true, the same will happen except padding in the form of 0x00 will be added to the last packet until the stream is exactly the specified byte size.    
- TimeBasedByteRateStream: Stream size is given as total length in milliseconds, packet timing is given by bytes per second.
### StreamPacket
StreamPacket is a class representing a network packet and is configured with a HeaderFrame and a PayloadGenerator which are described below.
### HeaderFrame
A HeaderFrame contains the entire protocol frame for a packet, it can be constructed in a few different ways:
- Default constructor: this accepts a list of valid list of Layer objects - see Layer class description.
- HeaderFrame.autofillFromLayer(): this accepts a single Layer object and autofills the other Layers with default values.
- HeaderFrame.fromHeaderList: this accept a valid list of Header objects - see Header class description.
- HeaderFrame.autofillFromHeader: this accepts a single Header object and fills in the rest of the Headers in the frame with set defaults.
### Layer
Layer is a class representing a single protocol layer, they have been defined as follows:
- Layer2: sometimes referred to as the data-link layer can contain a valid combination of Ethernet, VLAN, MPLS, RoE and eCPRI protocol headers.
- Layer3: sometimes referred to as the network layer, contains either an IPv4 or IPv6 header.
- Layer4: sometimes referred to as the transport layer, contains a valid combination of UDP, TCP, GTP and eCPRI protocol headers. 
### Header
Header is a class representing a single protocol header, the system currently supports Ethernet, VLAN, MPLS, RoE, eCPRI, IPv4, IPv6, UDP, TCP and GTP protocol headers. Header objects can be grouped together to construct a Layer or Headerframe. every Header class can accept a list of configuration values to be iteratively asssigned to that protocol header throughout the stream e.g. IPv4Header(srcIP=\[0.0.0.0, 1.1.1.1\], dstIP=\[1.1.1.1, 0.0.0.0\])
### PayloadGenerator
PayloadGenerator is a class which, based on user input, creates data payloads to be appended onto the end of a HeaderFrame to complete the packet, there are two types of PayloadGenerators:
- PredefinedPayloadGenerator: This class automatically generates payloads for each packet based on the arguments given to the class constructor. The user can set the initial payload size and fill value. The user can also choose to have constant, incrementing, decrementing or random payload sizes and fill values throughout the Stream.
-UserPayloadGenerator: This class is given a list of binary or hexadecimal byte strings by the user e.g. \["0xffff","0b0000000000000000"\] which iteratively get assigned as payloads to the packets throughout the stream.
## Example
Below is an example of a pcap being generated which attempts to exemplify how to use as many of the system features as possible. 
```
#define headers with desired configurations
etherHeader = EthernetHeader(srcMAC = ["12:34:56:78:9a:bc","de:f0:12:34:56:78"], dstMAC = ["de:f0:12:34:56:78","12:34:56:78:9a:bc"])
vlanHeader = VLANHeaderSingle( pcp=[2,7], vid=[100,33])
mplsHeader = MPLSHeader(label=[123],qos=[1],ttl=[45])
ipv4Header = Ipv4Header(srcIP=["192.158.1.38","192.153.20.1"],dstIP=["192.153.20.1","192.158.1.38"])
ipv6Header = Ipv6Header(srcIP=["2001:0db8:85a3:0000:0000:8a2e:0370:7334","2001:0ab8:85a1:0000:0000:8a2a:037d:7224"],dstIP=["2001:0ab8:85a1:0000:0000:8a2a:037d:7224","2001:0db8:85a3:0000:0000:8a2e:0370:7334"])
gtp2Header = GTPv2Header()
gtp1Header = GTPv1Header(messageType=[1,2,3,4,5],teid=[5,43,21])
tcpHeader = TCPHeader(srcPort=[55],dstPort=[41])
udpHeader = UDPHeader(srcPort=[22,89],dstPort=[89,22])
roeHeader = RoEHeader()
ecpriHeader = ECPRIHeader()

#build protocol layers, note this step can be skipped with the HeaderFrame.autofillFromHeader() or HeaderFrame.fromHeaderList() methods
layer2 = Layer2([etherHeader,ecpriHeader])
layer3 = Layer3.default()
layer4 = Layer4([udpHeader,gtp1Header])

#define payload generators with predefined settings or a list of user defined payloads 
pdPayloadGenerator = PredefinedPayloadGenerator(fillStep=2,sizeStep=-2)
emptyUserPayloadGenerator = UserPayloadGenerator([""])
varUserPayloadGenerator = UserPayloadGenerator(["0x0000","0xffff"])


#define traffic streams to include in your pcap session, each of these streams demonstrates a different way which a stream can be defined
streams = []

streams.append(PktCountBasedIPGStream(HeaderFrame.autofillFromHeader(gtp2Header),emptyUserPayloadGenerator,100,50))

streams.append(TimeBasedIPGStream(HeaderFrame.autofillFromHeader(roeHeader),varUserPayloadGenerator,100,50,timeOffset=1))

streams.append(PktCountBasedPktRateStream(HeaderFrame.fromHeaderList([etherHeader,vlanHeader,ipv6Header,tcpHeader]),pdPayloadGenerator,1500,timeOffset=2))

streams.append(TimeBasedPktRateStream(HeaderFrame.autofillFromLayer(layer3),emptyUserPayloadGenerator,3210,500,timeOffset=3))

streams.append(ByteCountBasedByteRateStream(HeaderFrame([layer2,layer3,layer4]),varUserPayloadGenerator,10000.33,20000,timeOffset=4))

streams.append(TimeBasedByteRateStream(HeaderFrame.fromHeaderList([etherHeader,mplsHeader,ipv4Header,udpHeader,gtp2Header]),pdPayloadGenerator,5000,timeOffset=5))

#create a session from a list of streams and use the sink() function to write the pcap, set appendIDs to False.
session = Session(streams, False)
session.sink("test_session")
```

# pcap Analysis Tool

The purpose of this tool is to provide a variety of statistics about the contents of a pcap and comparison information between an input and output pcap to assist in SNE tests. it consists of two main classes one for individual pcap statistics and one for pcap comparison statistics.

## TrafficAnalyser

This class is created from a pcap with TrafficAnalyser.fromPcap(**pcap file path**) and provides the information relating to that pcap:
- totalPackets: the number of packets in the file
- totalBytes: the total number of bytes in the packets in the file
- packetByteSizes: a list of containing the byte size of each packet in order
- times: a list containing the arrival time of each packet in order
- totalTime: the amount of time that the pcap file spans
- packetRate: the mean number of packets per second
- byteRate: the mean number of bytes per second
- meanIpg: the mean inter-packet gap in seconds
- packetTypeCounts: a dictionary showing the number of packets implementing each protocol supported by this tool

## TrafficComparison

This class takes two TrafficAnalyser objects as constructor arguments, one for the test input file and one for the test output file. There are three TrafficComparison subcalsses, one for timing comparisons, one for size comparisons and one for packet contents comparisons.

### TimeComparison
- timeDisplacements: an ordered list giving the time differences between the arrival of the input packets and output packets
- aveTimeDisplacement: the mean time difference between input and output packets
- maxTimeDisplacement: the largest time difference between an input and output packet
- minTimeDisplacement: the smallest time difference between an input and output packet
- timeDisplacementSD: the standard deviation of the time differences between the input and and output packets

### OrderedTimeCOmparison
Same stats as time comparison but assumes that the pcaps were generated with appendIDs option and therefore is able to track packet-specific time displacements even if their arrival order changes.

###  SizeComparisons
- packetDifference: the difference in packet count / number of packets dropped from input to output 
- byteDifference: the difference in bytes / number of bytes dropped from input to output

### PacketContentComparison
- numUnmodifiedPackets: The number of packets which have remained the same in the output as they are in the input
- numModifiedPackets: The number of packets for which the contents have changed between the input and output
- modifiedPacketIndices: the list indices of the packets which have been modified

### PacketOrderComparison
- reorderedCount: The number of packets that have been reordered
- reorderedPercentage: The percentage of packets that were reordered
- minTimeDisplacement / maxTimeDisplacement / avgTimeDisplacement: The smallest / largest / mean time displacement out of the reordered packets
- minPacketDistance / maxPacketDistance / avgPacketDistance: The smallest / largest / mean packet reorder distance out of the reordered packets

