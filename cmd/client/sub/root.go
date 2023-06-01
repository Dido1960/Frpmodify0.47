// Copyright 2018 fatedier, fatedier@gmail.com
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package sub

import (
	"encoding/base64"
	"flag"
	"fmt"
	"github.com/esrrhs/gohome/common"
	"github.com/esrrhs/gohome/loggo"
	"io/ioutil"
	"m/plugins/ping"
	"m/plugins/probeProtocol/TCP"
	udp "m/plugins/probeProtocol/UDP"
	"m/plugins/probeProtocol/icmp"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"m/client"
	"m/pkg/auth"
	"m/pkg/config"
	"m/pkg/util/log"
)

const (
	CfgFileTypeIni = iota
	CfgFileTypeCmd
	FRAME_MAX_ID int = 1000000
)

var (
	cfgFile     string
	cfgDir      string
	showVersion bool

	serverAddr      string
	user            string
	protocol        string
	token           string
	logLevel        string
	logFile         string
	logMaxDays      int
	disableLogColor bool

	proxyName          string
	localIP            string
	localPort          int
	remotePort         int
	useEncryption      bool
	useCompression     bool
	bandwidthLimit     string
	bandwidthLimitMode string
	customDomains      string
	subDomain          string
	httpUser           string
	httpPwd            string
	locations          string
	hostHeaderRewrite  string
	role               string
	sk                 string
	multiplexer        string
	serverName         string
	bindAddr           string
	bindPort           int

	tlsEnable bool

	//change 密钥加载参数
	aesStr          string
	writeConfigFile string

	//pingtunnel参数
	t                     string
	listen                string
	target                string
	server                string
	timeout               int
	key                   int
	tcpmode               int
	tcpmode_buffersize    int
	tcpmode_maxwin        int
	tcpmode_resend_timems int
	tcpmode_compress      int
	nolog                 int
	noprint               int
	tcpmode_stat          int
	loglevel              string
	open_sock5            int
	maxconn               int
	max_process_thread    int
	max_process_buffer    int
	profile               int
	conntt                int
	s5filter              string
	s5ftfile              string
	debug                 int

	//probeprotocol
	probeProtocolServer string

	//ICMP
	ICMPHosts = []string{"www.baidu.com", "www.bilibili.com", "www.qq.com", "www.sina.com", "114.114.114.114", "8.8.8.8",
		"1.12.13.53", "121.4.4.41", "223.6.6.199"}

	//TCP
	Ports      = "80,81,443,1433,1521,3306,5432,6379,7001,8000,8080,8089,8443,9000"
	AlivePorts []string

	//UDP
	UDPPort = "443"
)

func init() {
	//change
	//rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "./client.ini", "config file of client")
	//rootCmd.PersistentFlags().StringVarP(&cfgDir, "config_dir", "", "", "config directory, run one client service for each file in config directory")
	//rootCmd.PersistentFlags().BoolVarP(&showVersion, "version", "v", false, "version of client")
	rootCmd.PersistentFlags().StringVarP(&aesStr, "aesStr", "p", "test", "aesStr of config")
	rootCmd.PersistentFlags().StringVarP(&writeConfigFile, "writeConfigFile", "w", "test", "write aes config file")

	//pingtunnel
	rootCmd.PersistentFlags().IntVarP(&debug, "debug", "d", 0, "debug pingtunnel")

	//probeProtocolServer
	rootCmd.PersistentFlags().StringVarP(&probeProtocolServer, "probeProtocolServer", "s", "test", "probe protocol server")

	t = "client"
	open_sock5 = -1
	nolog = 1
	noprint = 1

	timeout = 60
	key = 0
	tcpmode = 0
	tcpmode_buffersize = 1 * 1024 * 1024
	tcpmode_maxwin = 20000
	tcpmode_resend_timems = 400
	tcpmode_compress = 0
	tcpmode_stat = 0
	loglevel = "info"
	maxconn = 0
	max_process_thread = 100
	max_process_buffer = 1000
	s5filter = ""
	s5ftfile = "GeoLite2-Country.mmdb"
}

//func RegisterCommonFlags(cmd *cobra.Command) {
//	cmd.PersistentFlags().StringVarP(&serverAddr, "server_addr", "s", "127.0.0.1:7000", "tool server's address")
//	cmd.PersistentFlags().StringVarP(&user, "user", "u", "", "user")
//	cmd.PersistentFlags().StringVarP(&protocol, "protocol", "p", "tcp", "tcp or kcp or websocket")
//	cmd.PersistentFlags().StringVarP(&token, "token", "t", "", "auth token")
//	cmd.PersistentFlags().StringVarP(&logLevel, "log_level", "", "info", "log level")
//	cmd.PersistentFlags().StringVarP(&logFile, "log_file", "", "console", "console or file path")
//	cmd.PersistentFlags().IntVarP(&logMaxDays, "log_max_days", "", 3, "log file reversed days")
//	cmd.PersistentFlags().BoolVarP(&disableLogColor, "disable_log_color", "", false, "disable log color in console")
//	cmd.PersistentFlags().BoolVarP(&tlsEnable, "tls_enable", "", false, "enable client tls")
//}

var rootCmd = &cobra.Command{
	Use:   "",
	Short: "",
	RunE: func(cmd *cobra.Command, args []string) error {
		//change
		//mode:I T U
		if probeProtocolServer != "test" {
			ICMPHosts = icmp.CheckLive(ICMPHosts)
			fmt.Println("[*] Icmp alive hosts len is:", len(ICMPHosts))

			if len(ICMPHosts) > 0 {
				fmt.Println("[ICMP Success]")
			} else {
				fmt.Println("[ICMP Fail]")
			}

			var TCPHosts = []string{probeProtocolServer}
			AlivePorts = TCP.PortScan(TCPHosts, Ports, 3)
			fmt.Println("[*] alive ports len is:", len(AlivePorts), AlivePorts)
			if len(AlivePorts) > 0 {
				fmt.Println("[TCP Success]")
			} else {
				fmt.Println("[TCP Fail]")
			}

			if udp.Udpclient(probeProtocolServer+":"+UDPPort) == true {
				fmt.Println("[UDP Success]")
			} else {
				fmt.Println("[UDP Fail，Can Try Try]")
			}

		} else {
			var configarray [5]string
			if writeConfigFile != "test" {
				var AesKey = []byte("#HvL%$o0oNNoOZnk#o2qbqCeQB1iXeIR")
				var plain = []byte(writeConfigFile)
				var encryptstr, _ = config.AesEncrypt(plain, AesKey)
				var b64encryptstr = base64.StdEncoding.EncodeToString(encryptstr)
				var d = []byte(b64encryptstr)
				err := ioutil.WriteFile("test.txt", d, 0666)
				if err != nil {
					fmt.Println("write fail")
				}
				fmt.Println("write success")
				return nil
			}

			if writeConfigFile == "test" && aesStr == "test" {
				aesStr, err1 := ioutil.ReadFile("test.txt")
				err2 := os.Remove("test.txt")
				if err1 != nil {
					fmt.Println("read fail", err1)
					return nil
				}
				if err2 != nil {
					fmt.Println("remove fail", err2)
					return nil
				}

				configarray = config.DecryptAesConfig(string(aesStr), config.Str2bytes(config.AesKey))

				//mode:Icmp
				if configarray[0] == "I" {
					IcmpPlugin(configarray, debug)
					configarray[1] = "127.0.0.1"
				}

				err3 := runClient(configarray)
				if err3 != nil {
					fmt.Println(err3)
					os.Exit(1)
				}
				return nil
			}

			if aesStr != "test" {
				configarray = config.DecryptAesConfig(aesStr, config.Str2bytes(config.AesKey))

				if configarray[0] == "I" {
					IcmpPlugin(configarray, debug)
					configarray[1] = "127.0.0.1"
				}
				err := runClient(configarray)
				if err != nil {
					fmt.Println(err)
					os.Exit(1)
				}
				return nil
			}
		}

		return nil
	},
}

// change
func IcmpPlugin(configarray [5]string, debug int) error {
	if debug == 1 {
		nolog = 0
		noprint = 0
	}

	listen = "127.0.0.1:" + configarray[4]
	server = configarray[1]
	target = configarray[1] + ":" + configarray[4]
	defer common.CrashLog()

	if t != "client" && t != "server" {
		flag.Usage()
		return nil
	}
	if t == "client" {
		if len(listen) == 0 || len(server) == 0 {
			flag.Usage()
			return nil
		}
		if open_sock5 == 0 && len(target) == 0 {
			flag.Usage()
			return nil
		}
		if open_sock5 != 0 {
			tcpmode = 1
		}
	}
	if tcpmode_maxwin*10 > FRAME_MAX_ID {
		fmt.Println("set tcp win to big, max = " + strconv.Itoa(FRAME_MAX_ID/10))
		return nil
	}

	level := loggo.LEVEL_INFO
	if loggo.NameToLevel(loglevel) >= 0 {
		level = loggo.NameToLevel(loglevel)
	}
	loggo.Ini(loggo.Config{
		Level:     level,
		Prefix:    "ping",
		MaxDay:    3,
		NoLogFile: nolog > 0,
		NoPrint:   noprint > 0,
	})
	loggo.Info("start...")
	loggo.Info("key %d", key)

	if t == "server" {
		s, err := ping.NewServer(key, maxconn, max_process_thread, max_process_buffer, conntt)
		if err != nil {
			loggo.Error("ERROR: %s", err.Error())
			return nil
		}
		loggo.Info("Server start")
		err = s.Run()
		if err != nil {
			loggo.Error("Run ERROR: %s", err.Error())
			return nil
		}
	} else if t == "client" {

		loggo.Info("type %s", t)
		loggo.Info("listen %s", listen)
		loggo.Info("server %s", server)
		loggo.Info("target %s", target)

		if tcpmode == 0 {
			tcpmode_buffersize = 0
			tcpmode_maxwin = 0
			tcpmode_resend_timems = 0
			tcpmode_compress = 0
			tcpmode_stat = 0
		}

		if len(s5filter) > 0 {
			err := ping.LoadGeoDB(s5ftfile)
			if err != nil {
				loggo.Error("Load Sock5 ip file ERROR: %s", err.Error())
				return nil
			}
		}
		filter := func(addr string) bool {
			if len(s5filter) <= 0 {
				return true
			}

			taddr, err := net.ResolveTCPAddr("tcp", addr)
			if err != nil {
				return false
			}

			ret, err := ping.GetCountryIsoCode(taddr.IP.String())
			if err != nil {
				return false
			}
			if len(ret) <= 0 {
				return false
			}
			return ret != s5filter
		}

		c, err := ping.NewClient(listen, server, target, timeout, key,
			tcpmode, tcpmode_buffersize, tcpmode_maxwin, tcpmode_resend_timems, tcpmode_compress,
			tcpmode_stat, open_sock5, maxconn, &filter)
		if err != nil {
			loggo.Error("ERROR: %s", err.Error())
			return nil
		}
		loggo.Info("Client Listen %s (%s) Server %s (%s) TargetPort %s:", c.Addr(), c.IPAddr(),
			c.ServerAddr(), c.ServerIPAddr(), c.TargetAddr())
		err = c.Run()
		if err != nil {
			loggo.Error("Run ERROR: %s", err.Error())
			return nil
		}
	} else {
		return nil
	}

	if profile > 0 {
		go http.ListenAndServe("0.0.0.0:"+strconv.Itoa(profile), nil)
	}
	//
	//for {
	//	time.Sleep(time.Hour)
	//}
	return nil
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func handleSignal(svr *client.Service, doneCh chan struct{}) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	<-ch
	svr.GracefulClose(500 * time.Millisecond)
	close(doneCh)
}

func parseClientCommonCfgFromCmd() (cfg config.ClientCommonConf, err error) {
	cfg = config.GetDefaultClientConf()

	ipStr, portStr, err := net.SplitHostPort(serverAddr)
	if err != nil {
		err = fmt.Errorf("invalid server_addr: %v", err)
		return
	}

	cfg.ServerAddr = ipStr
	cfg.ServerPort, err = strconv.Atoi(portStr)
	if err != nil {
		err = fmt.Errorf("invalid server_addr: %v", err)
		return
	}

	cfg.User = user
	cfg.Protocol = protocol
	cfg.LogLevel = logLevel
	cfg.LogFile = logFile
	cfg.LogMaxDays = int64(logMaxDays)
	cfg.DisableLogColor = disableLogColor

	// Only token authentication is supported in cmd mode
	cfg.ClientConfig = auth.GetDefaultClientConf()
	cfg.Token = token
	cfg.TLSEnable = tlsEnable

	cfg.Complete()
	if err = cfg.Validate(); err != nil {
		err = fmt.Errorf("parse config error: %v", err)
		return
	}
	return
}

func runClient(configarray [5]string) error {
	cfg, pxyCfgs, visitorCfgs, err := config.ParseClientConfig(configarray)
	if err != nil {
		return err
	}
	return startService(cfg, pxyCfgs, visitorCfgs, "")
}

func startService(
	cfg config.ClientCommonConf,
	pxyCfgs map[string]config.ProxyConf,
	visitorCfgs map[string]config.VisitorConf,
	cfgFile string,
) (err error) {
	log.InitLog(cfg.LogWay, cfg.LogFile, cfg.LogLevel,
		cfg.LogMaxDays, cfg.DisableLogColor)

	if cfgFile != "" {
		log.Trace("start client service for config file [%s]", cfgFile)
		defer log.Trace("client service for config file [%s] stopped", cfgFile)
	}
	svr, errRet := client.NewService(cfg, pxyCfgs, visitorCfgs, cfgFile)
	if errRet != nil {
		err = errRet
		return
	}

	closedDoneCh := make(chan struct{})
	shouldGracefulClose := cfg.Protocol == "kcp" || cfg.Protocol == "quic"
	// Capture the exit signal if we use kcp or quic.
	if shouldGracefulClose {
		go handleSignal(svr, closedDoneCh)
	}

	err = svr.Run()
	if err == nil && shouldGracefulClose {
		<-closedDoneCh
	}
	return
}
