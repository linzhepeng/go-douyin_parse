package main

import (
	"fmt"
	"io"
	"os"
	"path"
	"sort"
	"strings"

	"github.com/dreadl0ck/gopcap"
	"github.com/jayi/golog"
)

// TCP	用于记录单个TCP分组信息
type TCP struct {
	SrcIP   string
	DstIP   string
	SrcPort int
	DstPort int
	Seq     int
	Flag    byte
	Data    []byte
}

// Connection 用于保存一个完整连接
type Connection struct {
	Client    []*TCP
	ClientKey string
	Server    []*TCP
	ServerKey string
	URIKey    string
}

//调试的时候打印日志用的计数变量
var i = 1

func main() {
	args := os.Args
	if len(args) < 2 || args == nil {
		fmt.Println("./pcap.exe xx.pcap")
		return
	}
	path := args[1]
	// 获取总共有多少分组
	cnt, err := gopcap.Count(path)
	fmt.Println("total:", cnt, err)

	// create reader
	r, err := gopcap.Open(path)
	if err != nil {
		panic(err)
	}
	defer r.Close()

	tcpDatas := make([]*TCP, 0)
	// 循环读取整个文件中的分组
	for {
		_, data, err := r.ReadNextPacket()
		if err != nil {
			if err == io.EOF {
				println("EOF")
				break
			}
			panic(err)
		}
		fmt.Println(i)
		// 从数据中解析出TCP信息
		tcp := parseTCP(data)
		if tcp != nil {
			tcpDatas = append(tcpDatas, tcp)
		}
		i++
	}
	// 将源目地址一致的tcp分组视作一个连接
	connections := parseConnection(tcpDatas)
	// 将数据写入磁盘
	writeConnections(connections)
}

func parseTCP(data []byte) *TCP {
	// 过滤以太网帧
	ipLayer := data[14:]
	// IP版本号，过滤IPV6
	ipVersion := ipLayer[0] >> 4
	if ipVersion == 6 {
		return nil
	}
	// 源目IP地址
	srcIP, dstIP := inetToIP(ipLayer[12:16]), inetToIP(ipLayer[16:20])
	//ip头部长度
	ipLayerHeaderLen := (ipLayer[0] & 15) * 4
	//分组总长度
	totalLen := inetToInt(ipLayer[2:4])
	// tcp层信息
	tcpLayer := ipLayer[ipLayerHeaderLen:totalLen]
	// 源目端口号
	srcPort := inetToInt(tcpLayer[:2])
	dstPort := inetToInt(tcpLayer[2:4])
	// 序列号
	seq := inetToInt(tcpLayer[4:8])
	//ack := inetToInt(tcpLayer[8:12])
	headerLen := (tcpLayer[12] >> 4) * 4
	flag := tcpLayer[13]
	// body部分
	payload := tcpLayer[int(headerLen):]
	//golog.Infof("%d src port: %d, dst port: %d, flag: %d, seq: %d, ack: %d, header len: %d, data len: %d",
	// i, srcPort, dstPort, flag, seq, ack, headerLen, len(payload))
	return &TCP{
		SrcIP:   srcIP,
		DstIP:   dstIP,
		SrcPort: srcPort,
		DstPort: dstPort,
		Seq:     seq,
		Flag:    flag,
		Data:    payload,
	}
}

func writeConnections(connections []*Connection) {
	for _, c := range connections {
		// 只取服务器返回的数据
		tcps := c.Server
		sort.Slice(tcps, func(i, j int) bool {
			return tcps[i].Seq < tcps[j].Seq
		})
		writeTCPS(tcps)
	}
}

func writeTCPS(tcps []*TCP) {
	var fp *os.File
	for j, tcp := range tcps {
		if len(tcp.Data) == 0 {
			continue
		}
		// 忽略重复的包
		if j > 0 && tcp.Seq == tcps[j-1].Seq && len(tcps[j-1].Data) > 0 {
			continue
		}
		fileName, dataRange, realData := getFileName(tcp.Data)
		if fileName == "" && fp == nil {
			continue
		}
		if fileName != "" {
			if fp != nil {
				fp.Close()
			}
			fp, _ = ForceOpenFile("./data/" + fileName + "/" + dataRange + ".mp4")
		}
		//fp.Write(tcp.Data)
		fp.Write(realData)
	}
}

// 以HTTP头部的content-range字段来命名文件
// 举例：content-range字段格式：Content-range:bytes0-499/1234   以1234为文件夹名，0-499为文件名
func getFileName(data []byte) (string, string, []byte) {
	if len(data) <= 4 || string(data[:4]) != "HTTP" {
		return "", "", data
	}
	dataRange := ""
	lines := strings.Split(string(data), "\r\n")
	for _, line := range lines {
		s := strings.Split(line, ":")
		if len(s) < 2 {
			continue
		}
		if s[0] == "Content-Range" {
			dataRange = strings.TrimSpace(s[1])
			break
		}
	}
	if dataRange == "" {
		return "", "", data
	}
	dataRange = strings.TrimPrefix(dataRange, "bytes ")
	s := strings.Split(dataRange, "/")
	if len(s) < 2 {
		golog.Fatal(s)
	}

	return s[1], s[0], []byte(lines[len(lines)-1])
}

// 这一步的作用是防止创建文件报错
// 例如在C盘创建 a/b 文件，如果原先磁盘中没有a文件夹就会报错，这里添加了逻辑，没有a文件夹就先创建a文件夹
func ForceOpenFile(file string) (*os.File, error) {
	dir, _ := path.Split(file)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		err = os.MkdirAll(dir, os.ModePerm)
		if err != nil {
			return nil, err
		}
	}
	return os.OpenFile(file, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
}

// 分析TCP包，将源目地址一致的TCP包打包成一个connection
func parseConnection(tcps []*TCP) []*Connection {
	m := make(map[string][]*TCP)
	for _, tcp := range tcps {
		if tcp.SrcPort == 443 || tcp.DstPort == 443 {
			continue
		}
		key := fmt.Sprintf("%s_%s_%d_%d", tcp.SrcIP, tcp.DstIP, tcp.SrcPort, tcp.DstPort)
		m[key] = append(m[key], tcp)
	}

	connections := make([]*Connection, 0)
	writeKey := make(map[string]bool)
	for key, value := range m {
		split := strings.Split(key, "_")
		// 服务器返回的数据，源目地址刚好相反
		reverseKey := fmt.Sprintf("%s_%s_%s_%s", split[1], split[0], split[3], split[2])
		reverseValue := m[reverseKey]
		if writeKey[key] {
			continue
		}
		writeKey[key] = true
		writeKey[reverseKey] = true
		// 分组可能乱序到达，这里按序列号排序
		sort.Slice(value, func(i, j int) bool {
			return value[i].Seq < value[j].Seq
		})
		sort.Slice(reverseValue, func(i, j int) bool {
			return reverseValue[i].Seq < reverseValue[j].Seq
		})
		if len(reverseValue) == 0 {
			golog.Error("not find ", reverseKey)
			continue
		}
		// flag=2 表示是客户端发的syn包 即tcp3握手，如果第一个包不是握手消息，则不记录该连接
		if value[0].Flag != 2 && reverseValue[0].Flag != 2 {
			continue
		}
		c := &Connection{
			Client:    value,
			ClientKey: key,
			Server:    reverseValue,
			ServerKey: reverseKey,
		}
		// 确保reverseValue存储的是服务器返回的TCP包
		if reverseValue[0].Flag == 2 {
			c.Client, c.Server = reverseValue, value
			c.ClientKey, c.ServerKey = reverseKey, key
		}
		golog.Infof("connection, client key %s | %d, server key %s | %d", c.ClientKey, len(c.Client), c.ServerKey, len(c.Server))
		connections = append(connections, c)
	}
	return connections
}

// 将格式转化为ip地址的格式
func inetToIP(data []byte) string {
	return fmt.Sprintf("%d.%d.%d.%d", byte(data[0]), byte(data[1]), byte(data[2]), byte(data[3]))
}

// 16进制转10进制
func inetToInt(data []byte) int {
	res := 0
	for _, d := range data {
		res = res*256 + int(d)
	}
	return res
}
