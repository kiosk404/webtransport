/**
* @Author: kiosk
* @Mail: weijiaxiang007@foxmail.com
* @Date: 2021/1/22
**/
package main

import (
	"quic-web-transport"
	"quic-web-transport/utils"
)

func main() {
	server := webtransport.NewWebTransportServerQuic(webtransport.Config{
		ListenAddr:     "0.0.0.0:4433",
		TLSCertPath:    "server.crt",
		TLSKeyPath:     "server.key",
		AllowedOrigins: []string{"localhost", "googlechrome.github.io"},
	})
	if err := server.Run(); err != nil {
		utils.Logging.Fatal().Err(err)
	}
}