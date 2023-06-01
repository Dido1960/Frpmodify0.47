package TCP

//
//import (
//	"net/http"
//	"testing"
//)
//
//func TestTcpServer(t *testing.T) {
//	finish := make(chan bool)
//
//	server1 := http.NewServeMux()
//	server1.HandleFunc("/", foo)
//
//	//var Ports = "80,81,443,1433,1521,3306,5432,6379,7001,8000,8080,8089,8443,9000"
//	go func() {
//		http.ListenAndServe(":80", server1)
//	}()
//
//	go func() {
//		http.ListenAndServe(":81", server1)
//	}()
//
//	go func() {
//		http.ListenAndServe(":443", server1)
//	}()
//
//	go func() {
//		http.ListenAndServe(":1433", server1)
//	}()
//	go func() {
//		http.ListenAndServe(":1521", server1)
//	}()
//
//	go func() {
//		http.ListenAndServe(":3306", server1)
//	}()
//
//	go func() {
//		http.ListenAndServe(":5432", server1)
//	}()
//
//	go func() {
//		http.ListenAndServe(":6379", server1)
//	}()
//
//	go func() {
//		http.ListenAndServe(":7001", server1)
//	}()
//
//	go func() {
//		http.ListenAndServe(":8000", server1)
//	}()
//
//	go func() {
//		http.ListenAndServe(":8080", server1)
//	}()
//	go func() {
//		http.ListenAndServe(":8089", server1)
//	}()
//
//	go func() {
//		http.ListenAndServe(":8443", server1)
//	}()
//
//	go func() {
//		http.ListenAndServe(":9000", server1)
//	}()
//	<-finish
//}
//func foo(w http.ResponseWriter, r *http.Request) {
//	w.Write([]byte("Listening on"))
//}
