package main

import (
	"errors"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"log"
	"path"
)

type PktInfo struct {
	SrcIP   string
	DstIP   string
	SrcPort uint16
	DstPort uint16
}

type Head struct {
	num  uint32
	list *Node
}

type Node struct {
	seq_s uint32
	seq_e uint32
	next  *Node
}

var PktStat map[PktInfo](*Head)

func init() {
	log.Println("init hash data")
	PktStat = make(map[PktInfo]*Head, 1000)
}

func HandlePcap(filename string) (bool, error) {
	if path.Ext(filename) != ".pcap" {
		return false, errors.New("后缀非PCAP格式")
	} else {
		return parsePcap(filename)
	}
}

func clearTable() {
	for pktinfo, head := range PktStat {
		for node := head.list; node != nil; { //遍历释放
			tmp := node
			node = node.next
			tmp.next = nil
		}
		delete(PktStat, pktinfo)
	}
}

func parsePcap(filename string) (bool, error) {
	// Open file instead of device
	handle, err := pcap.OpenOffline(filename)
	if err != nil {
		return false, err
	}
	defer handle.Close()
	pktInfo := PktInfo{}

	clearTable()
	num := 0
	var seq uint32
	var payloadlen int
	// Loop through packets in file
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		num += 1
		log.Println("start to parse pkt :", num)
		//check gtp
		layer := packet.Layers()
		if len(layer) >= 6 { //包含gtp隧道
			l4layer := layer[5]
			if l4layer.LayerType() == layers.LayerTypeTCP {
				tcp, _ := l4layer.(*layers.TCP)

				pktInfo.SrcPort = uint16(tcp.SrcPort)
				pktInfo.DstPort = uint16(tcp.DstPort)
				seq = tcp.Seq

				payloadlen = len(tcp.Payload)
				if payloadlen == 0 && (tcp.SYN || tcp.FIN) {
					payloadlen = 1
				}
			} else { //非tcp直接继续
				continue
			}
			//解析ip层
			l3layer := layer[4]
			if l3layer.LayerType() == layers.LayerTypeIPv4 {
				ip, _ := l3layer.(*layers.IPv4)
				pktInfo.SrcIP = ip.SrcIP.String()
				pktInfo.DstIP = ip.DstIP.String()
			} else if l3layer.LayerType() == layers.LayerTypeIPv6 {
				ip, _ := l3layer.(*layers.IPv6)
				pktInfo.SrcIP = ip.SrcIP.String()
				pktInfo.DstIP = ip.DstIP.String()
			}
			statPkt(&pktInfo, seq, payloadlen)
		}
	}
	return true, nil
}

func statPkt(pkt *PktInfo, seqStart uint32, payloadlen int) {
	log.Println("stat pkt ", payloadlen)
	seqEnd := seqStart + uint32(payloadlen)
	head, ok := PktStat[*pkt]
	if ok { //已经添加过
		log.Println("%v", head)
	} else { //未添加过
		node := Node{seqStart, seqEnd, nil}
		PktStat[*pkt] = &Head{1, &node}
		return
	}
	//遍历链表并插入
	head.num += 1
	//遍历插入
	if seqStart <= seqEnd {
		head.list = insert(head.list, seqStart, seqEnd)
	} else {
		head.list = insert(head.list, seqStart, ^uint32(0))
		head.list = insert(head.list, 0, seqEnd)
	}
	merge(head.list)
}

// 遍历连边插入
func insert(node *Node, seqS, seqE uint32) *Node {
	//与节点比较
	if seqE < node.seq_s { //比第一个节点小，插入后返回
		return &Node{seqS, seqE, node}
	}
	p1 := node
	for {
		if p1.seq_e < seqS {
			if p1.next == nil { //无后节点直接，插入最后
				p1.next = &Node{seqS, seqE, nil}
				return node
			} else if seqE < p1.next.seq_s { //插入两个节点中间
				p1.next = &Node{seqS, seqE, p1.next}
				return node
			} else {
				p1 = p1.next
			}
		} else { //与当前节点重叠或包含
			if seqS < p1.seq_s {
				p1.seq_s = seqS
			}
			if seqE > p1.seq_e {
				p1.seq_e = seqE
			}
			return node
		}
	}
	return node
}

func merge(node *Node) {
	p1 := node
	p2 := node.next
	for p2 != nil {
		if p1.seq_e >= p2.seq_s { //满足合并条件
			if p2.seq_e > p1.seq_e {
				p1.seq_e = p2.seq_e
			}
			p1.next = p2.next
			p2.next = nil
			p2 = p1.next
		} else {
			p1 = p2
			p2 = p2.next
		}
	}
}
