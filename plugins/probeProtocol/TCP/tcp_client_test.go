package TCP

import (
	"fmt"
	"testing"
)

//var (
//	Hosts      = []string{"1.117.73.197"}
//	Ports      = "80,81,443,1433,1521,3306,5432,6379,7001,8000,8080,8089,8443,9000"
//	AlivePorts []string
//)
//
//type Addr struct {
//	ip   string
//	port int
//}
//
//const (
//	THREADS int = 10
//)
//
//func PortScan(hostslist []string, ports string, timeout int64) []string {
//	var AliveAddress []string
//	probePorts := ParsePort(ports)
//	workers := THREADS
//	Addrs := make(chan Addr, len(hostslist)*len(probePorts))
//	results := make(chan string, len(hostslist)*len(probePorts))
//	var wg sync.WaitGroup
//
//	//接收结果
//	go func() {
//		for found := range results {
//			AliveAddress = append(AliveAddress, found)
//			wg.Done()
//		}
//	}()
//
//	//多线程扫描
//	for i := 0; i < workers; i++ {
//		go func() {
//			for addr := range Addrs {
//				PortConnect(addr, results, timeout, &wg)
//				wg.Done()
//			}
//		}()
//	}
//
//	//添加扫描目标
//	for _, port := range probePorts {
//		for _, host := range hostslist {
//			wg.Add(1)
//			Addrs <- Addr{host, port}
//		}
//	}
//	wg.Wait()
//	close(Addrs)
//	close(results)
//	return AliveAddress
//}
//
//func PortConnect(addr Addr, respondingHosts chan<- string, adjustedTimeout int64, wg *sync.WaitGroup) {
//	host, port := addr.ip, addr.port
//	conn, err := WrapperTcpWithTimeout("tcp4", fmt.Sprintf("%s:%v", host, port), time.Duration(adjustedTimeout)*time.Second)
//	defer func() {
//		if conn != nil {
//			conn.Close()
//		}
//	}()
//	if err == nil {
//		address := host + ":" + strconv.Itoa(port)
//		//result := fmt.Sprintf("%s open", address)
//		//common.LogSuccess(result)
//		wg.Add(1)
//		respondingHosts <- address
//	}
//}
//
//func ParsePort(ports string) (scanPorts []int) {
//	if ports == "" {
//		return
//	}
//	slices := strings.Split(ports, ",")
//	for _, port := range slices {
//		port = strings.TrimSpace(port)
//		if port == "" {
//			continue
//		}
//		upper := port
//		if strings.Contains(port, "-") {
//			ranges := strings.Split(port, "-")
//			if len(ranges) < 2 {
//				continue
//			}
//
//			startPort, _ := strconv.Atoi(ranges[0])
//			endPort, _ := strconv.Atoi(ranges[1])
//			if startPort < endPort {
//				port = ranges[0]
//				upper = ranges[1]
//			} else {
//				port = ranges[1]
//				upper = ranges[0]
//			}
//		}
//		start, _ := strconv.Atoi(port)
//		end, _ := strconv.Atoi(upper)
//		for i := start; i <= end; i++ {
//			scanPorts = append(scanPorts, i)
//		}
//	}
//	scanPorts = removeDuplicate(scanPorts)
//	return scanPorts
//}
//
//func removeDuplicate(old []int) []int {
//	result := []int{}
//	temp := map[int]struct{}{}
//	for _, item := range old {
//		if _, ok := temp[item]; !ok {
//			temp[item] = struct{}{}
//			result = append(result, item)
//		}
//	}
//	return result
//}
//
//func WrapperTcpWithTimeout(network, address string, timeout time.Duration) (net.Conn, error) {
//	d := &net.Dialer{Timeout: timeout}
//	return WrapperTCP(network, address, d)
//}
//
//func WrapperTCP(network, address string, forward *net.Dialer) (net.Conn, error) {
//	//get conn
//	var conn net.Conn
//	var err error
//	conn, err = forward.Dial(network, address)
//	if err != nil {
//		return nil, err
//	}
//	return conn, nil
//}

func TestTcpClient(t *testing.T) {
	AlivePorts = PortScan(Hosts, Ports, 3)
	fmt.Println("[*] alive ports len is:", len(AlivePorts), AlivePorts)
	if len(AlivePorts) > 0 {
		fmt.Println("TCP NORMAL")
	}
}
