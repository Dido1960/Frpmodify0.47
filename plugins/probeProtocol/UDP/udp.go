package udp

import (
	"github.com/antelman107/net-wait-go/wait"
	"time"
)

func Udpclient(addr string) bool {

	if !wait.New(
		wait.WithProto("udp"),
		wait.WithUDPPacket([]byte{
			0x54, 0x53,
			0x6F, 0x75, 0x72, 0x63, 0x65, 0x20,
			0x45, 0x6E, 0x67, 0x69, 0x6E, 0x65,
			0x20, 0x51, 0x75, 0x65, 0x72, 0x79,
			0x00}),
		wait.WithDebug(true),
		wait.WithDeadline(time.Second*5),
	).Do([]string{addr}) {
		//logger.Error("db is not available")
		return false
	}
	return true
}
