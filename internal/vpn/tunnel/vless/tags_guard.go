//go:build !with_utls

package vless

var _ int = "package internal/vpn/tunnel/vless requires build tag with_utls"
