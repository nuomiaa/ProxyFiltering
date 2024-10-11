@echo off
set GOARCH=amd64
set GOOS=linux
go build -ldflags "-w -s" ProxyFiltering+.go
upx ProxyFiltering+
del pf
rename ProxyFiltering+ pf+