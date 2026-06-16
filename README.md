# Python DNS Server and Client

这是一个计算机网络课程大作业项目，包含：

- DNS 服务器：解析 UDP DNS 请求，支持 A / AAAA / CNAME，本地 JSON 记录、上游递归查询、SQLite TTL 缓存。
- DNSSEC 签名验证：可选启用 `--dnssec`，验证上游响应的 RRSIG/DNSKEY/DS 签名链，提升解析安全性。
- 启发式预加载：自动分析查询关联规则，后台预加载常见关联域名降低后续查询延迟。
- A 记录轮询负载均衡：本地 JSON 的多条 A 记录按轮询方式返回，支持简单的本地负载分发。
- DNS 客户端：类似 `dig`，支持 `@server`、端口、记录类型，输出 Header / Question / Answer / Authority / Additional。
- DGA 恶意域名拦截：支持加载轻量级机器学习模型，对疑似 DGA 域名返回 REFUSED 或 Sinkhole 地址。
- 文档：设计文档和操作手册。

## 快速开始

```powershell
conda env create -f environment.yml
conda activate dns-lab
python -m unittest tests.py
python dns_server.py --host 127.0.0.1 --port 8053 --config records.json
```

另开一个终端：

```powershell
conda activate dns-lab
python dns_client.py @127.0.0.1 -p 8053 example.local A
python dns_client.py @127.0.0.1 -p 8053 alias.local CNAME
python dns_client.py @127.0.0.1 -p 8053 example.com A
```

若要启用拦截并返回 Sinkhole 地址：

```powershell
python dns_server.py --host 127.0.0.1 --port 8053 --config records.json --dga-model models/dga_model.joblib --dga-action sinkhole
```

若要启用 DNSSEC 验证：

```powershell
python dns_server.py --host 127.0.0.1 --port 8053 --config records.json --upstream 8.8.8.8 --dnssec
```

启用启发式预加载：

- 预加载功能默认开启，无需额外参数。
- 服务器会自动分析查询历史，发现关联规则后后台请求并缓存关联域名，提升后续访问命中率。

本地 A 记录负载均衡：

- 对于 `records.json` 中同一域名的多条 `A` 记录，服务器会采用轮询方式依次返回不同地址，提供简单本地负载分发。

更多说明见：

- [docs/design.md](docs/design.md)
- [docs/manual.md](docs/manual.md)
