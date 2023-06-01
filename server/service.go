// Copyright 2017 fatedier, fatedier@gmail.com
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

package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strconv"
	"time"

	"github.com/fatedier/golib/net/mux"
	fmux "github.com/hashicorp/yamux"
	quic "github.com/quic-go/quic-go"

	"m/pkg/auth"
	"m/pkg/config"
	"m/pkg/msg"
	"m/pkg/nathole"
	plugin "m/pkg/plugin/server"
	"m/pkg/transport"
	"m/pkg/util/log"
	toolNet "m/pkg/util/net"
	"m/pkg/util/tcpmux"
	"m/pkg/util/util"
	"m/pkg/util/version"
	"m/pkg/util/vhost"
	"m/pkg/util/xlog"
	"m/server/controller"
	"m/server/group"
	"m/server/metrics"
	"m/server/ports"
	"m/server/proxy"
	"m/server/visitor"

	wxworkbot "github.com/vimsucks/wxwork-bot-go"
)

const (
	connReadTimeout       time.Duration = 10 * time.Second
	vhostReadWriteTimeout time.Duration = 30 * time.Second
)

// Server service
type Service struct {
	// Dispatch connections to different handlers listen on same port
	muxer *mux.Mux

	// Accept connections from client
	listener net.Listener

	// Accept connections using kcp
	kcpListener net.Listener

	// Accept connections using quic
	quicListener quic.Listener

	// Accept connections using websocket
	websocketListener net.Listener

	// Accept tool tls connections
	tlsListener net.Listener

	// Manage all controllers
	ctlManager *ControlManager

	// Manage all proxies
	pxyManager *proxy.Manager

	// Manage all plugins
	pluginManager *plugin.Manager

	// HTTP vhost router
	httpVhostRouter *vhost.Routers

	// All resource managers and controllers
	rc *controller.ResourceController

	// Verifies authentication based on selected method
	authVerifier auth.Verifier

	tlsConfig *tls.Config

	cfg config.ServerCommonConf
}

func NewService(cfg config.ServerCommonConf) (svr *Service, err error) {
	tlsConfig, err := transport.NewServerTLSConfig(
		cfg.TLSCertFile,
		cfg.TLSKeyFile,
		cfg.TLSTrustedCaFile)
	if err != nil {
		return
	}

	svr = &Service{
		ctlManager:    NewControlManager(),
		pxyManager:    proxy.NewManager(),
		pluginManager: plugin.NewManager(),
		rc: &controller.ResourceController{
			VisitorManager: visitor.NewManager(),
			TCPPortManager: ports.NewManager("tcp", cfg.ProxyBindAddr, cfg.AllowPorts),
			UDPPortManager: ports.NewManager("udp", cfg.ProxyBindAddr, cfg.AllowPorts),
		},
		httpVhostRouter: vhost.NewRouters(),
		authVerifier:    auth.NewAuthVerifier(cfg.ServerConfig),
		tlsConfig:       tlsConfig,
		cfg:             cfg,
	}

	// Create tcpmux httpconnect multiplexer.
	if cfg.TCPMuxHTTPConnectPort > 0 {
		var l net.Listener
		address := net.JoinHostPort(cfg.ProxyBindAddr, strconv.Itoa(cfg.TCPMuxHTTPConnectPort))
		l, err = net.Listen("tcp", address)
		if err != nil {
			err = fmt.Errorf("create server listener error, %v", err)
			return
		}

		svr.rc.TCPMuxHTTPConnectMuxer, err = tcpmux.NewHTTPConnectTCPMuxer(l, cfg.TCPMuxPassthrough, vhostReadWriteTimeout)
		if err != nil {
			err = fmt.Errorf("create vhost tcpMuxer error, %v", err)
			return
		}
		log.Info("tcpmux httpconnect multiplexer listen on %s, passthough: %v", address, cfg.TCPMuxPassthrough)
	}

	// Init all plugins
	pluginNames := make([]string, 0, len(cfg.HTTPPlugins))
	for n := range cfg.HTTPPlugins {
		pluginNames = append(pluginNames, n)
	}
	sort.Strings(pluginNames)

	for _, name := range pluginNames {
		svr.pluginManager.Register(plugin.NewHTTPPluginOptions(cfg.HTTPPlugins[name]))
		log.Info("plugin [%s] has been registered", name)
	}
	svr.rc.PluginManager = svr.pluginManager

	// Init group controller
	svr.rc.TCPGroupCtl = group.NewTCPGroupCtl(svr.rc.TCPPortManager)

	// Init HTTP group controller
	svr.rc.HTTPGroupCtl = group.NewHTTPGroupController(svr.httpVhostRouter)

	// Init TCP mux group controller
	svr.rc.TCPMuxGroupCtl = group.NewTCPMuxGroupCtl(svr.rc.TCPMuxHTTPConnectMuxer)

	// Init 404 not found page
	vhost.NotFoundPagePath = cfg.Custom404Page

	var (
		httpMuxOn  bool
		httpsMuxOn bool
	)
	if cfg.BindAddr == cfg.ProxyBindAddr {
		if cfg.BindPort == cfg.VhostHTTPPort {
			httpMuxOn = true
		}
		if cfg.BindPort == cfg.VhostHTTPSPort {
			httpsMuxOn = true
		}
	}

	// Listen for accepting connections from client.
	address := net.JoinHostPort(cfg.BindAddr, strconv.Itoa(cfg.BindPort))
	ln, err := net.Listen("tcp", address)
	if err != nil {
		err = fmt.Errorf("create server listener error, %v", err)
		return
	}

	svr.muxer = mux.NewMux(ln)
	svr.muxer.SetKeepAlive(time.Duration(cfg.TCPKeepAlive) * time.Second)
	go func() {
		_ = svr.muxer.Serve()
	}()
	ln = svr.muxer.DefaultListener()

	svr.listener = ln
	log.Info("server tcp listen on %s", address)

	// Listen for accepting connections from client using kcp protocol.
	if cfg.KCPBindPort > 0 {
		address := net.JoinHostPort(cfg.BindAddr, strconv.Itoa(cfg.KCPBindPort))
		svr.kcpListener, err = toolNet.ListenKcp(address)
		if err != nil {
			err = fmt.Errorf("listen on kcp udp address %s error: %v", address, err)
			return
		}
		log.Info("server kcp listen on udp %s", address)
	}

	if cfg.QUICBindPort > 0 {
		address := net.JoinHostPort(cfg.BindAddr, strconv.Itoa(cfg.QUICBindPort))
		quicTLSCfg := tlsConfig.Clone()
		quicTLSCfg.NextProtos = []string{"tool"}
		svr.quicListener, err = quic.ListenAddr(address, quicTLSCfg, &quic.Config{
			MaxIdleTimeout:     time.Duration(cfg.QUICMaxIdleTimeout) * time.Second,
			MaxIncomingStreams: int64(cfg.QUICMaxIncomingStreams),
			KeepAlivePeriod:    time.Duration(cfg.QUICKeepalivePeriod) * time.Second,
		})
		if err != nil {
			err = fmt.Errorf("listen on quic udp address %s error: %v", address, err)
			return
		}
		log.Info("server quic listen on quic %s", address)
	}

	// Listen for accepting connections from client using websocket protocol.
	websocketPrefix := []byte("GET " + toolNet.ToolWebsocketPath)
	websocketLn := svr.muxer.Listen(0, uint32(len(websocketPrefix)), func(data []byte) bool {
		return bytes.Equal(data, websocketPrefix)
	})
	svr.websocketListener = toolNet.NewWebsocketListener(websocketLn)

	// Create http vhost muxer.
	if cfg.VhostHTTPPort > 0 {
		rp := vhost.NewHTTPReverseProxy(vhost.HTTPReverseProxyOptions{
			ResponseHeaderTimeoutS: cfg.VhostHTTPTimeout,
		}, svr.httpVhostRouter)
		svr.rc.HTTPReverseProxy = rp

		address := net.JoinHostPort(cfg.ProxyBindAddr, strconv.Itoa(cfg.VhostHTTPPort))
		server := &http.Server{
			Addr:    address,
			Handler: rp,
		}
		var l net.Listener
		if httpMuxOn {
			l = svr.muxer.ListenHttp(1)
		} else {
			l, err = net.Listen("tcp", address)
			if err != nil {
				err = fmt.Errorf("create vhost http listener error, %v", err)
				return
			}
		}
		go func() {
			_ = server.Serve(l)
		}()
		log.Info("http service listen on %s", address)
	}

	// Create https vhost muxer.
	if cfg.VhostHTTPSPort > 0 {
		var l net.Listener
		if httpsMuxOn {
			l = svr.muxer.ListenHttps(1)
		} else {
			address := net.JoinHostPort(cfg.ProxyBindAddr, strconv.Itoa(cfg.VhostHTTPSPort))
			l, err = net.Listen("tcp", address)
			if err != nil {
				err = fmt.Errorf("create server listener error, %v", err)
				return
			}
			log.Info("https service listen on %s", address)
		}

		svr.rc.VhostHTTPSMuxer, err = vhost.NewHTTPSMuxer(l, vhostReadWriteTimeout)
		if err != nil {
			err = fmt.Errorf("create vhost httpsMuxer error, %v", err)
			return
		}
	}

	// tool tls listener
	svr.tlsListener = svr.muxer.Listen(2, 1, func(data []byte) bool {
		// tls first byte can be 0x16 only when vhost https port is not same with bind port
		return int(data[0]) == toolNet.TOOLTLSHeadByte || int(data[0]) == 0x16
	})

	// Create nat hole controller.
	if cfg.BindUDPPort > 0 {
		var nc *nathole.Controller
		address := net.JoinHostPort(cfg.BindAddr, strconv.Itoa(cfg.BindUDPPort))
		nc, err = nathole.NewController(address)
		if err != nil {
			err = fmt.Errorf("create nat hole controller error, %v", err)
			return
		}
		svr.rc.NatHoleController = nc
		log.Info("nat hole udp service listen on %s", address)
	}

	//change delete dashboard
	//var statsEnable bool
	// Create dashboard web server.
	//if cfg.DashboardPort > 0 {
	//	// Init dashboard assets
	//	assets.Load(cfg.AssetsDir)
	//
	//	address := net.JoinHostPort(cfg.DashboardAddr, strconv.Itoa(cfg.DashboardPort))
	//	err = svr.RunDashboardServer(address)
	//	if err != nil {
	//		err = fmt.Errorf("create dashboard web server error, %v", err)
	//		return
	//	}
	//	log.Info("Dashboard listen on %s", address)
	//	statsEnable = true
	//}
	//if statsEnable {
	//	modelmetrics.EnableMem()
	//	if cfg.EnablePrometheus {
	//		modelmetrics.EnablePrometheus()
	//	}
	//}
	return
}

func (svr *Service) Run() {
	if svr.rc.NatHoleController != nil {
		go svr.rc.NatHoleController.Run()
	}
	if svr.kcpListener != nil {
		go svr.HandleListener(svr.kcpListener)
	}
	if svr.quicListener != nil {
		go svr.HandleQUICListener(svr.quicListener)
	}

	go svr.HandleListener(svr.websocketListener)
	go svr.HandleListener(svr.tlsListener)

	svr.HandleListener(svr.listener)
}

// change
// /全部代理状态定时推送
func (svr *Service) ProxyStatsPush() {

	//t := time.Now().Second()
	t := time.Now().Hour()
	if t == 14 || t == 10 || t == 20 || t == 2 {

		//fmt.Println(svr.cfg.BOTKey)
		proxyInfoResp := GetProxyInfoResp{}
		proxyInfoResp.Proxies = svr.getProxyStatsByType("tcp")

		buf, _ := json.Marshal(&proxyInfoResp)
		//fmt.Println(string(buf))

		var info = map[string]interface{}{}
		err := json.Unmarshal(buf, &info)
		if err != nil {
			fmt.Println("11111")
			return
		}

		Proxy, ok := info["proxies"].([]interface{})
		if !ok {
			//log.Print("失败")
			fmt.Println("2222")
			return
		}
		var online string
		var offline string
		online = ""
		offline = ""

		var onlinenum int
		var offlinenum int
		onlinenum = 0
		offlinenum = 0

		for _, v := range Proxy {
			Proxyinfo := v.(map[string]interface{})
			if Proxyinfo["status"] == "online" {
				onlinenum = onlinenum + 1
				online = online + InterfaceToString(Proxyinfo["name"]) + "、"
			} else {
				offlinenum = offlinenum + 1
				offline = offline + InterfaceToString(Proxyinfo["name"]) + "、"
			}
		}

		bot := wxworkbot.New(svr.cfg.BOTKey)
		str := "# <font color=LightSeaGreen>【代理状态推送】</font>\n" +
			"<font face=黑体>----------------</font>\n" +
			"<font face=黑体>当前在线代理总计：" + strconv.Itoa(onlinenum) + "</font>\n" +
			"<font face=黑体>当前在线代理名称：" + online + "</font>\n" +
			"<font face=黑体>----------------</font>\n" +
			"<font face=黑体>当前掉线代理总计：" + strconv.Itoa(offlinenum) + "</font>\n" +
			"<font face=黑体>当前掉线代理名称：" + offline + "</font>"
		// Markdown 消息
		markdown := wxworkbot.Markdown{
			Content: str,
		}
		err = bot.Send(markdown)
		if err != nil {
			fmt.Println(err)
		}
	}

	//name:test status:online
}

// 接口类型转字符串
func InterfaceToString(value interface{}) (s string) {
	var key string
	if value == nil {
		return key
	}

	switch value.(type) {
	case float64:
		ft := value.(float64)
		key = strconv.FormatFloat(ft, 'f', -1, 64)
	case float32:
		ft := value.(float32)
		key = strconv.FormatFloat(float64(ft), 'f', -1, 64)
	case int:
		it := value.(int)
		key = strconv.Itoa(it)
	case uint:
		it := value.(uint)
		key = strconv.Itoa(int(it))
	case int8:
		it := value.(int8)
		key = strconv.Itoa(int(it))
	case uint8:
		it := value.(uint8)
		key = strconv.Itoa(int(it))
	case int16:
		it := value.(int16)
		key = strconv.Itoa(int(it))
	case uint16:
		it := value.(uint16)
		key = strconv.Itoa(int(it))
	case int32:
		it := value.(int32)
		key = strconv.Itoa(int(it))
	case uint32:
		it := value.(uint32)
		key = strconv.Itoa(int(it))
	case int64:
		it := value.(int64)
		key = strconv.FormatInt(it, 10)
	case uint64:
		it := value.(uint64)
		key = strconv.FormatUint(it, 10)
	case string:
		key = value.(string)
	case []byte:
		key = string(value.([]byte))
	default:
		newValue, _ := json.Marshal(value)
		key = string(newValue)
	}

	return key
}

func (svr *Service) handleConnection(ctx context.Context, conn net.Conn) {
	xl := xlog.FromContextSafe(ctx)

	var (
		rawMsg msg.Message
		err    error
	)

	_ = conn.SetReadDeadline(time.Now().Add(connReadTimeout))
	if rawMsg, err = msg.ReadMsg(conn); err != nil {
		log.Trace("Failed to read message: %v", err)
		conn.Close()
		return
	}
	_ = conn.SetReadDeadline(time.Time{})

	switch m := rawMsg.(type) {
	case *msg.Login:
		// server plugin hook
		content := &plugin.LoginContent{
			Login:         *m,
			ClientAddress: conn.RemoteAddr().String(),
		}
		retContent, err := svr.pluginManager.Login(content)
		if err == nil {
			m = &retContent.Login
			err = svr.RegisterControl(conn, m)
		}

		// If login failed, send error message there.
		// Otherwise send success message in control's work goroutine.
		if err != nil {
			xl.Warn("register control error: %v", err)
			_ = msg.WriteMsg(conn, &msg.LoginResp{
				Version: version.Full(),
				Error:   util.GenerateResponseErrorString("register control error", err, svr.cfg.DetailedErrorsToClient),
			})
			conn.Close()
		}
	case *msg.NewWorkConn:
		if err := svr.RegisterWorkConn(conn, m); err != nil {
			conn.Close()
		}
	case *msg.NewVisitorConn:
		if err = svr.RegisterVisitorConn(conn, m); err != nil {
			xl.Warn("register visitor conn error: %v", err)
			_ = msg.WriteMsg(conn, &msg.NewVisitorConnResp{
				ProxyName: m.ProxyName,
				Error:     util.GenerateResponseErrorString("register visitor conn error", err, svr.cfg.DetailedErrorsToClient),
			})
			conn.Close()
		} else {
			_ = msg.WriteMsg(conn, &msg.NewVisitorConnResp{
				ProxyName: m.ProxyName,
				Error:     "",
			})
		}
	default:
		log.Warn("Error message type for the new connection [%s]", conn.RemoteAddr().String())
		conn.Close()
	}
}

func (svr *Service) HandleListener(l net.Listener) {
	// Listen for incoming connections from client.
	for {
		c, err := l.Accept()
		if err != nil {
			log.Warn("Listener for incoming connections from client closed")
			return
		}
		// inject xlog object into net.Conn context
		xl := xlog.New()
		ctx := context.Background()

		c = toolNet.NewContextConn(xlog.NewContext(ctx, xl), c)

		log.Trace("start check TLS connection...")
		originConn := c
		var isTLS, custom bool
		c, isTLS, custom, err = toolNet.CheckAndEnableTLSServerConnWithTimeout(c, svr.tlsConfig, svr.cfg.TLSOnly, connReadTimeout)
		if err != nil {
			log.Warn("CheckAndEnableTLSServerConnWithTimeout error: %v", err)
			originConn.Close()
			continue
		}
		log.Trace("check TLS connection success, isTLS: %v custom: %v", isTLS, custom)

		// Start a new goroutine to handle connection.
		go func(ctx context.Context, clientonn net.Conn) {
			if svr.cfg.TCPMux {
				fmuxCfg := fmux.DefaultConfig()
				fmuxCfg.KeepAliveInterval = time.Duration(svr.cfg.TCPMuxKeepaliveInterval) * time.Second
				fmuxCfg.LogOutput = io.Discard
				session, err := fmux.Server(clientonn, fmuxCfg)
				if err != nil {
					log.Warn("Failed to create mux connection: %v", err)
					clientonn.Close()
					return
				}

				for {
					stream, err := session.AcceptStream()
					if err != nil {
						log.Debug("Accept new mux stream error: %v", err)
						session.Close()
						return
					}
					go svr.handleConnection(ctx, stream)
				}
			} else {
				svr.handleConnection(ctx, clientonn)
			}
		}(ctx, c)
	}
}

func (svr *Service) HandleQUICListener(l quic.Listener) {
	// Listen for incoming connections from client.
	for {
		c, err := l.Accept(context.Background())
		if err != nil {
			log.Warn("QUICListener for incoming connections from client closed")
			return
		}
		// Start a new goroutine to handle connection.
		go func(ctx context.Context, clientonn quic.Connection) {
			for {
				stream, err := clientonn.AcceptStream(context.Background())
				if err != nil {
					log.Debug("Accept new quic mux stream error: %v", err)
					_ = clientonn.CloseWithError(0, "")
					return
				}
				go svr.handleConnection(ctx, toolNet.QuicStreamToNetConn(stream, clientonn))
			}
		}(context.Background(), c)
	}
}

func (svr *Service) RegisterControl(ctlConn net.Conn, loginMsg *msg.Login) (err error) {
	// If client's RunID is empty, it's a new client, we just create a new controller.
	// Otherwise, we check if there is one controller has the same run id. If so, we release previous controller and start new one.
	if loginMsg.RunID == "" {
		loginMsg.RunID, err = util.RandID()
		if err != nil {
			return
		}
	}

	ctx := toolNet.NewContextFromConn(ctlConn)
	xl := xlog.FromContextSafe(ctx)
	xl.AppendPrefix(loginMsg.RunID)
	ctx = xlog.NewContext(ctx, xl)
	xl.Info("client login info: ip [%s] version [%s] hostname [%s] os [%s] arch [%s]",
		ctlConn.RemoteAddr().String(), loginMsg.Version, loginMsg.Hostname, loginMsg.Os, loginMsg.Arch)

	// Check client version.
	if ok, msg := version.Compat(loginMsg.Version); !ok {
		err = fmt.Errorf("%s", msg)
		return
	}

	// Check auth.
	if err = svr.authVerifier.VerifyLogin(loginMsg); err != nil {
		return
	}

	ctl := NewControl(ctx, svr.rc, svr.pxyManager, svr.pluginManager, svr.authVerifier, ctlConn, loginMsg, svr.cfg)
	if oldCtl := svr.ctlManager.Add(loginMsg.RunID, ctl); oldCtl != nil {
		oldCtl.allShutdown.WaitDone()
	}

	ctl.Start()

	// for statistics
	metrics.Server.NewClient()

	go func() {
		// block until control closed
		ctl.WaitClosed()
		svr.ctlManager.Del(loginMsg.RunID, ctl)
	}()
	return
}

// RegisterWorkConn register a new work connection to control and proxies need it.
func (svr *Service) RegisterWorkConn(workConn net.Conn, newMsg *msg.NewWorkConn) error {
	xl := toolNet.NewLogFromConn(workConn)
	ctl, exist := svr.ctlManager.GetByID(newMsg.RunID)
	if !exist {
		xl.Warn("No client control found for run id [%s]", newMsg.RunID)
		return fmt.Errorf("no client control found for run id [%s]", newMsg.RunID)
	}
	// server plugin hook
	content := &plugin.NewWorkConnContent{
		User: plugin.UserInfo{
			User:  ctl.loginMsg.User,
			Metas: ctl.loginMsg.Metas,
			RunID: ctl.loginMsg.RunID,
		},
		NewWorkConn: *newMsg,
	}
	retContent, err := svr.pluginManager.NewWorkConn(content)
	if err == nil {
		newMsg = &retContent.NewWorkConn
		// Check auth.
		err = svr.authVerifier.VerifyNewWorkConn(newMsg)
	}
	if err != nil {
		xl.Warn("invalid NewWorkConn with run id [%s]", newMsg.RunID)
		_ = msg.WriteMsg(workConn, &msg.StartWorkConn{
			Error: util.GenerateResponseErrorString("invalid NewWorkConn", err, ctl.serverCfg.DetailedErrorsToClient),
		})
		return fmt.Errorf("invalid NewWorkConn with run id [%s]", newMsg.RunID)
	}
	return ctl.RegisterWorkConn(workConn)
}

func (svr *Service) RegisterVisitorConn(visitorConn net.Conn, newMsg *msg.NewVisitorConn) error {
	return svr.rc.VisitorManager.NewConn(newMsg.ProxyName, visitorConn, newMsg.Timestamp, newMsg.SignKey,
		newMsg.UseEncryption, newMsg.UseCompression)
}
