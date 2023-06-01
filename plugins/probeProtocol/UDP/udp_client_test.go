package udp

import (
	"fmt"
	"testing"
)

func TestUdpclient(t *testing.T) {
	if Udpclient("1.117.73.197:443") == true {
		fmt.Println("UDP NORMAL")
	}
}
