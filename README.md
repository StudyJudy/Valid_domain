# XDNS

```
#   __   _______  _   _  _____ 
#   \ \ / /  __ \| \ | |/ ____|
#    \ V /| |  | |  \| | (___  
#     > < | |  | | . ' |\___ \
#    / . \| |__| | |\  |____) |
#   /_/ \_\_____/|_| \_|_____/
```
🔍 **XDNS** is a high-speed DNS domain validation tool that checks **domain lists** using **multiple resolvers** and **raw socket packet crafting** for maximum speed.

📦 **Version:** v1.0.0  
✨ **Supports:** high-speed DNS validation with rotating resolvers and customizable verbosity

---

## 🚀 Features

- ⚡ High-performance DNS domain validation
- 📋 Supports domain list input (one domain per line)
- 🔁 Supports multiple DNS resolvers with rotation
- 🛠️ Low-level control via raw sockets (requires interface, MAC/IP setup)
- 🧾 Customizable output file
- 📉 Fine-grained logging with verbosity levels (`-v`)
- 🔍 Dry-run mode for debugging

---

## 🛠️ Usage

```bash
sudo ./xdns -domainlist domains.txt -iface ens34 -srcip 202.112.47.150 -srcmac 00:0c:29:95:4c:5f -gtwmac ac:74:09:b8:c3:00 -dnsfile resolvers.txt -out result.txt
```

---

## ⚙️ Command-Line Options

| Flag          | Description                                                                                     |
| ------------- | ----------------------------------------------------------------------------------------------- |
| `-domainlist` | Path to domain list file (one domain per line, required)                                        |
| `-iface`      | Network interface to send packets (e.g., `ens34`)                                                |
| `-srcip`      | Source IP address                                                                               |
| `-srcmac`     | Source MAC address                                                                              |
| `-gtwmac`     | Gateway MAC address                                                                             |
| `-rate`       | Query rate (QPS), default: `1000`                                                               |
| `-dnsfile`    | DNS server list file (optional, defaults to `8.8.8.8`)                                          |
| `-dnsList`    | DNS server IP list with comma separated (optional, defaults to `8.8.8.8`)                       |
| `-out`        | Output file name, default: `result-<date>.txt`                                                  |
| `-dry`        | Dry run mode (does not send packets, just prints domains and DNS servers)                       |
| `-wtgtime`    | Waiting time (s) until exit, default: `5`                                                       |
| `-v`          | Verbosity level: <br> `0`: silent <br> `1`: only results <br> `2`: +progress <br> `3`: all logs |
| `-V`          | Print version and exit                                                                          |

---

## 🧪 Examples

### 基本用法

```bash
sudo ./xdns -domainlist test_domains.txt -dnsfile resolvers.txt -iface ens34 -srcip 202.112.47.150 -srcmac 00:0c:29:95:4c:5f -gtwmac ac:74:09:b8:c3:00
```

### 使用多个DNS服务器

```bash
sudo ./xdns -domainlist domains.txt -dnsList "8.8.8.8,1.1.1.1,208.67.222.222" -iface ens34 -srcip 202.112.47.150 -srcmac 00:0c:29:95:4c:5f -gtwmac ac:74:09:b8:c3:00
```

### Dry Run模式

```bash
./xdns -domainlist domains.txt -dnsfile resolvers.txt -dry
```

### 域名列表文件格式

创建一个 `domains.txt` 文件，每行一个域名：
```
google.com
baidu.com
github.com
stackoverflow.com
example.com
```

---

## 🧭 Verbosity Control (`-v`)

| Level | Description                                  |
| ----- | -------------------------------------------- |
| `0`   | Silent mode (no logs)                        |
| `1`   | Only print valid subdomains                  |
| `2`   | Print progress (e.g., sent/received count)   |
| `3`   | Full logs: sent/recv progress + lines stored |

> 💡 Press `Enter` during execution in `-v 1` mode to view current progress!

---

## 📄 Output

所有有效的域名会被写入输出文件（默认：`result-<date>.txt`），格式为纯文本，每行包含域名和对应的IP地址：

```
google.com,142.250.191.14
baidu.com,110.242.68.66
github.com,140.82.112.3
```

---

## ⚠️ Requirements

* Linux with raw socket support
* Root privileges (`sudo`)
* Proper network interface and MAC/IP setup
* Go 1.18+

---

## 📦 Build

```bash
go build -o xdns xdns.go
```

---

## 📜 Copyright

XDNS Copyright 2025-2025 Xiang Li from All-in-One Security and Privacy Lab (AOSP Lab) Nankai University

