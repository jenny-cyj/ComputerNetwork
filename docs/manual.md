# 操作手册

## 1. 环境依赖

- Conda 或 Miniconda。
- Python 3.11，随 `dns-lab` conda 环境自动安装。
- 第三方库：`dnslib`、`scikit-learn`、`joblib`。
- 标准库：`socket`、`sqlite3`、`json`、`argparse`、`csv`。

创建环境：

```powershell
conda env create -f environment.yml
conda activate dns-lab
```

环境已经创建过时，只需要激活：

```powershell
conda activate dns-lab
```

重新安装依赖：

```powershell
conda run -n dns-lab pip install -r requirements.txt
```

验证依赖：

```powershell
conda run -n dns-lab python -c "from importlib.metadata import version; print(version('dnslib')); print(version('scikit-learn'))"
```

运行离线测试：

```powershell
conda run -n dns-lab python -m unittest tests.py
```

## 2. 文件说明

```text
dns_server.py          DNS 服务器
dns_client.py          DNS 客户端查询工具
dns_cache.py           SQLite 缓存模块
dns_records.py         本地 JSON 记录模块
dga_features.py        DGA 域名字符串特征提取
dga_data.py            DGA 数据集加载、抽样和统计
dga_detector.py        DGA 模型加载和运行时判定
train_dga_model.py     DGA 数据加载、模型训练和保存
inspect_datasets.py    数据集规模统计工具
environment.yml        Conda 环境配置，环境名 dns-lab
requirements.txt       pip 依赖清单
records.json           本地域名配置
dns_cache.sqlite3      运行时自动生成的缓存数据库
docs/design.md         设计文档
docs/manual.md         操作手册
```

## 3. 本地域名配置

配置文件为 JSON，默认路径是 `records.json`。

```json
{
  "example.local": {
    "A": [
      {
        "value": "192.168.10.10",
        "ttl": 300
      }
    ],
    "AAAA": [
      {
        "value": "2001:db8::10",
        "ttl": 300
      }
    ]
  },
  "alias.local": {
    "CNAME": [
      {
        "value": "example.local",
        "ttl": 300
      }
    ]
  }
}
```

字段说明：

- 顶层键：域名。
- 二级键：记录类型，支持 `A`、`AAAA`、`CNAME`。
- `value`：记录值。
- `ttl`：生存时间，单位为秒。

## 4. 启动服务器

普通用户推荐使用 `8053` 端口，避开 Windows 上常见的 `53` 和 `5353` 端口冲突：

```powershell
conda activate dns-lab
python dns_server.py --host 127.0.0.1 --port 8053 --config records.json
```

指定上游 DNS：

```powershell
python dns_server.py --host 127.0.0.1 --port 8053 --upstream 8.8.8.8
```

服务器启动后会一直监听请求，这是正常现象。退出服务器可以在服务器终端按 `Ctrl+C`；如果 VS Code 终端无法中断，可以点击终端右上角的垃圾桶图标结束终端。

## 5. 客户端查询

查询本地 A 记录：

```powershell
python dns_client.py @127.0.0.1 -p 8053 example.local A
```

查询本地 AAAA 记录：

```powershell
python dns_client.py @127.0.0.1 -p 8053 example.local AAAA
```

查询本地 CNAME 记录：

```powershell
python dns_client.py @127.0.0.1 -p 8053 alias.local CNAME
```

查询公网域名，触发上游递归查询和缓存：

```powershell
python dns_client.py @127.0.0.1 -p 8053 example.com A
```

客户端输出包括 Header、Question、Answer、Authority、Additional。

## 6. DGA 恶意域名拦截


### 启用拦截

拒绝解析恶意域名：

```powershell
python dns_server.py --host 127.0.0.1 --port 8053 --config records.json --dga-model models/dga_model.joblib --dga-action refuse
```

返回 Sinkhole 地址：

```powershell
python dns_server.py --host 127.0.0.1 --port 8053 --config records.json --dga-model models/dga_model.joblib --dga-action sinkhole
```

指定阈值和 Sinkhole 地址：

```powershell
python dns_server.py --host 127.0.0.1 --port 8053 --dga-model models/dga_model.joblib --dga-threshold 0.7 --dga-action sinkhole --sinkhole-ipv4 0.0.0.0 --sinkhole-ipv6 ::
```

服务器日志示例：

```text
query name=abcxyz123example.com type=A
dga score name=abcxyz123example.com score=0.9321 malicious=True
dga blocked name=abcxyz123example.com action=sinkhole type=A
```

## 7. DNSSEC 与启发式预加载

### DNSSEC 验证

启用 DNSSEC 后，服务器会验证来自上游 DNS 的响应签名，确保返回的记录通过 RRSIG、DNSKEY 和 DS 链验证。

```powershell
python dns_server.py --host 127.0.0.1 --port 8053 --config records.json --upstream 8.8.8.8 --dnssec
```

验证失败时，服务器会在日志中输出 `[DNSSEC]` 错误信息，当前实现可用于检测上游响应的完整性。

### 启发式预加载

启发式预加载默认开启，服务器会记录最近查询并自动发现关联域名，例如主站域名和其 CDN/静态资源域名之间的关系。满足频率阈值后，后台会触发预加载并将关联域名缓存到 `dns_cache.sqlite3`。常见日志如下：

```text
[RULES] Found 2 prefix domains with 5 associations
preload triggered domain=g.alicdn.com trigger_by=www.taobao.com frequency=5
preload success domain=g.alicdn.com type=A ttl=3600
```

### 本地 A 记录负载均衡

如果 `records.json` 中某个域名有多条 `A` 记录，若对该域名发起多次查询，服务器会按轮询顺序返回这些地址，实现简单的本地负载均衡：

```json
"example.local": {
  "A": [
    {"value": "192.168.10.10", "ttl": 300},
    {"value": "192.168.10.11", "ttl": 300}
  ]
}
```

同一域名的连续查询会轮流返回 `192.168.10.10`、`192.168.10.11`，提高本地服务可用性。

## 8. 常见问题

### 启动时报 WinError 10013

常见原因是端口被占用、端口被系统保留，或监听低端口时权限不足。建议优先使用 `8053`。

检查端口占用：

```powershell
netstat -ano -p udp | findstr ":8053"
```

### 公网域名查询超时

可能原因：

- 当前网络无法访问 `8.8.8.8`。
- 防火墙阻止 UDP 53。
- 校园网或运营商限制外部 DNS。

可以改用其他上游 DNS：

```powershell
python dns_server.py --host 127.0.0.1 --port 8053 --upstream 1.1.1.1
```

### 如何清空缓存

停止服务器后删除 `dns_cache.sqlite3`，下次启动会自动重建。

## 8. 验收建议

1. 启动服务器监听 `127.0.0.1:8053`。
2. 查询 `example.local A`，证明本地 A 记录响应。
3. 查询 `example.local AAAA`，证明 IPv6 记录响应。
4. 查询 `alias.local CNAME`，证明别名记录响应。
5. 查询 `example.com A` 两次，观察服务器日志中第一次为上游查询，第二次为缓存命中。
6. 验证智能恶意域名拦截：加载 DGA 模型后查询疑似恶意域名如`eqwzjxk.com`，观察服务器返回 REFUSED 或 Sinkhole 地址。
7. 验证 DNSSEC：启用 DNSSEC，查询一个已启用 DNSSEC 的域名如 `google.com`，在服务器日志中查找 `[DNSSEC]` 前缀的验证输出，确认出现类似 `RRSIG validation result: True` 的消息。
8. 验证启发式预加载：先查询 `www.taobao.com` 多次，然后查询 `g.alicdn.com`，观察服务器日志出现`[RULES] found`和`preload success`等输出，后续对被预加载域名的查询应显著降低上游访问延迟并显示 `cache hit`。
9. 验证本地 A 记录轮询负载均衡：在 `records.json` 中为同一域名添加多条 `A` 记录，对该域名连续发起多次查询，检查返回的 `A` 地址是否按顺序轮换。
