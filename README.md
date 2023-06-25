# GoDNS

基于 libuv 库实现的 Linux DNS 服务器

## 项目特点


- 支持 DNS 报文转发、缓存与自定义解析
- 基于 RB Tree 与 LRU 实现 DNS 缓存，性能优异
- 支持并发查询，采用序号池与查询池实现

## 配置与使用

### 环境配置

- Linux 系统，推荐使用 WSL 以便在 Windows 下使用
- 需要安装 CMake 与 libuv 库
```
$ apt install cmake -y
$ apt install libuv1-dev -y
```
- 需要配置 DNS 服务器地址
```
$ sudo vim /etc/resolv.conf
(nameserver 127.0.0.1)
```

### 编译运行

进入项目目录，执行以下命令即可编译程序
```
$ chmod +x build.sh
$ ./build.sh
```
进入 build 目录，执行以下命令即可运行程序
```
$ sudo ./main
```
注意，程序需要 sudo 权限监听 53 端口