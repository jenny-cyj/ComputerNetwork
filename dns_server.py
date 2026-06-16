import argparse
import hashlib
import socket
import struct
import threading
import time
from collections import deque, defaultdict
from typing import Iterable, Optional, Deque, Dict, List, Tuple

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.backends import default_backend
from dnslib import A, AAAA, DNSHeader, DNSRecord, QTYPE, RCODE, RR

from dns_cache import DNSCache
from dga_detector import DGAClassifier, load_detector
from dns_records import LocalRecords, SUPPORTED_TYPES, normalize_name



def qtype_name(qtype_code: int) -> str:
    return QTYPE.get(qtype_code, str(qtype_code))


class DNSSECValidator:
    """DNSSEC 签名验证类，支持 RRSIG 签名链验证"""
    
    # DNSSEC 算法常量
    RSAKEY_MD5 = 1
    RSAKEY_SHA1 = 5
    RSAKEY_SHA256 = 8
    RSAKEY_SHA512 = 10
    ECDSAP256SHA256 = 13
    ECDSAP384SHA384 = 14
    ED25519 = 15
    ED448 = 16
    
    # DS 摘要算法
    DS_SHA1 = 1
    DS_SHA256 = 2
    DS_SHA384 = 4
    
    def __init__(self):
        self.trusted_keys: Dict[str, bytes] = {}  # {zone: public_key}
        self.key_cache: Dict[str, Tuple[bytes, int]] = {}  # {zone: (key, expiry_time)}
        self.validation_cache: Dict[str, bool] = {}  # {signature_data: valid}
        
    def validate_rrsig(
        self,
        rrsig_data: bytes,
        rrset_data: bytes,
        dnskey_data: bytes,
        algorithm: int
    ) -> bool:
        """
        验证 RRSIG 签名
        
        Args:
            rrsig_data: RRSIG 记录的签名部分
            rrset_data: 被签名的资源记录集数据
            dnskey_data: 用于验证的 DNSKEY 公钥
            algorithm: DNSSEC 算法类型
            
        Returns:
            签名是否有效
        """
        try:
            # 检查缓存
            cache_key = hashlib.sha256(rrsig_data + rrset_data).hexdigest()
            if cache_key in self.validation_cache:
                return self.validation_cache[cache_key]
            
            result = False
            
            if algorithm in (self.RSAKEY_MD5, self.RSAKEY_SHA1, 
                            self.RSAKEY_SHA256, self.RSAKEY_SHA512):
                result = self._verify_rsa_signature(rrsig_data, rrset_data, dnskey_data, algorithm)
            elif algorithm in (self.ECDSAP256SHA256, self.ECDSAP384SHA384):
                result = self._verify_ecdsa_signature(rrsig_data, rrset_data, dnskey_data, algorithm)
            elif algorithm in (self.ED25519, self.ED448):
                result = self._verify_eddsa_signature(rrsig_data, rrset_data, dnskey_data, algorithm)
            
            # 缓存结果
            self.validation_cache[cache_key] = result
            
            print(f"[DNSSEC] RRSIG validation result: {result}, algorithm={algorithm}")
            return result
            
        except Exception as e:
            print(f"[DNSSEC] RRSIG validation error: {e}")
            return False
    
    def _verify_rsa_signature(
        self,
        signature: bytes,
        data: bytes,
        public_key_data: bytes,
        algorithm: int
    ) -> bool:
        """验证 RSA 签名"""
        try:
            # 提取公钥
            public_key = self._extract_rsa_public_key(public_key_data)
            if not public_key:
                return False
            
            # 选择哈希算法
            hash_algo = self._get_rsa_hash_algorithm(algorithm)
            if not hash_algo:
                return False
            
            # 验证签名
            public_key.verify(
                signature,
                data,
                padding.PKCS1v15(),
                hash_algo
            )
            print(f"[DNSSEC] RSA signature verified successfully")
            return True
            
        except Exception as e:
            print(f"[DNSSEC] RSA signature verification failed: {e}")
            return False
    
    def _verify_ecdsa_signature(
        self,
        signature: bytes,
        data: bytes,
        public_key_data: bytes,
        algorithm: int
    ) -> bool:
        """验证 ECDSA 签名"""
        try:
            # 提取公钥
            public_key = self._extract_ecdsa_public_key(public_key_data, algorithm)
            if not public_key:
                return False
            
            # 选择哈希算法
            hash_algo = self._get_ecdsa_hash_algorithm(algorithm)
            if not hash_algo:
                return False
            
            # 验证签名
            public_key.verify(signature, data, ec.ECDSA(hash_algo))
            print(f"[DNSSEC] ECDSA signature verified successfully")
            return True
            
        except Exception as e:
            print(f"[DNSSEC] ECDSA signature verification failed: {e}")
            return False
    
    def _verify_eddsa_signature(
        self,
        signature: bytes,
        data: bytes,
        public_key_data: bytes,
        algorithm: int
    ) -> bool:
        """验证 EdDSA 签名（ED25519/ED448）"""
        try:
            # EdDSA 验证需要特殊处理，这里提供基础支持框架
            print(f"[DNSSEC] EdDSA signature verification not fully implemented (algorithm={algorithm})")
            # 实际应用中需要使用专门的 EdDSA 库
            return False
            
        except Exception as e:
            print(f"[DNSSEC] EdDSA signature verification error: {e}")
            return False
    
    def _extract_rsa_public_key(self, key_data: bytes):
        """从 DNSKEY 数据中提取 RSA 公钥"""
        try:
            if len(key_data) < 3:
                return None
            
            # 跳过前 3 个字节（标志）
            key_data = key_data[3:]
            
            # 按照 RFC 3110 格式提取公钥指数和模数
            if len(key_data) < 1:
                return None
            
            exponent_len = key_data[0]
            if exponent_len == 0:
                # 3 字节长度格式
                if len(key_data) < 3:
                    return None
                exponent_len = struct.unpack(">H", key_data[1:3])[0]
                exponent = key_data[3:3+exponent_len]
                modulus = key_data[3+exponent_len:]
            else:
                exponent = key_data[1:1+exponent_len]
                modulus = key_data[1+exponent_len:]
            
            if not modulus or not exponent:
                return None
            
            # 转换为整数
            e = int.from_bytes(exponent, byteorder='big')
            n = int.from_bytes(modulus, byteorder='big')
            
            # 构建 RSA 公钥对象
            public_key = rsa.RSAPublicNumbers(e, n).public_key(default_backend())
            return public_key
            
        except Exception as e:
            print(f"[DNSSEC] Error extracting RSA public key: {e}")
            return None
    
    def _extract_ecdsa_public_key(self, key_data: bytes, algorithm: int):
        """从 DNSKEY 数据中提取 ECDSA 公钥"""
        try:
            if len(key_data) < 3:
                return None
            
            # 跳过前 3 个字节
            key_data = key_data[3:]
            
            # 根据算法确定曲线
            if algorithm == self.ECDSAP256SHA256:
                curve = ec.SECP256R1()
                expected_len = 64  # 2 * 32 字节
            elif algorithm == self.ECDSAP384SHA384:
                curve = ec.SECP384R1()
                expected_len = 96  # 2 * 48 字节
            else:
                return None
            
            if len(key_data) != expected_len:
                print(f"[DNSSEC] Invalid ECDSA key length: {len(key_data)} != {expected_len}")
                return None
            
            # 提取 X 和 Y 坐标
            mid = expected_len // 2
            x = int.from_bytes(key_data[:mid], byteorder='big')
            y = int.from_bytes(key_data[mid:], byteorder='big')
            
            # 构建 ECDSA 公钥对象
            public_key = ec.EllipticCurvePublicNumbers(x, y, curve).public_key(default_backend())
            return public_key
            
        except Exception as e:
            print(f"[DNSSEC] Error extracting ECDSA public key: {e}")
            return None
    
    def _get_rsa_hash_algorithm(self, algorithm: int):
        """获取 RSA 对应的哈希算法"""
        if algorithm == self.RSAKEY_MD5:
            return hashes.MD5()
        elif algorithm == self.RSAKEY_SHA1:
            return hashes.SHA1()
        elif algorithm == self.RSAKEY_SHA256:
            return hashes.SHA256()
        elif algorithm == self.RSAKEY_SHA512:
            return hashes.SHA512()
        return None
    
    def _get_ecdsa_hash_algorithm(self, algorithm: int):
        """获取 ECDSA 对应的哈希算法"""
        if algorithm == self.ECDSAP256SHA256:
            return hashes.SHA256()
        elif algorithm == self.ECDSAP384SHA384:
            return hashes.SHA384()
        return None
    
    def validate_ds_record(
        self,
        dnskey_data: bytes,
        ds_digest: bytes,
        ds_algorithm: int,
        key_tag: int
    ) -> bool:
        """
        验证 DS 记录与 DNSKEY 的链
        
        Args:
            dnskey_data: DNSKEY 记录数据
            ds_digest: DS 记录中的摘要
            ds_algorithm: DS 摘要算法
            key_tag: DNSKEY 的 key tag
            
        Returns:
            DS 记录是否与 DNSKEY 匹配
        """
        try:
            # 计算 DNSKEY 的摘要
            calculated_digest = self._compute_ds_digest(dnskey_data, ds_algorithm)
            if not calculated_digest:
                return False
            
            result = calculated_digest == ds_digest
            print(f"[DNSSEC] DS record validation: {result}")
            return result
            
        except Exception as e:
            print(f"[DNSSEC] DS record validation error: {e}")
            return False
    
    def _compute_ds_digest(self, dnskey_data: bytes, algorithm: int) -> Optional[bytes]:
        """计算 DNSKEY 的 DS 摘要"""
        try:
            if algorithm == self.DS_SHA1:
                return hashlib.sha1(dnskey_data).digest()
            elif algorithm == self.DS_SHA256:
                return hashlib.sha256(dnskey_data).digest()
            elif algorithm == self.DS_SHA384:
                return hashlib.sha384(dnskey_data).digest()
            else:
                print(f"[DNSSEC] Unsupported DS digest algorithm: {algorithm}")
                return None
                
        except Exception as e:
            print(f"[DNSSEC] Error computing DS digest: {e}")
            return None
    
    def validate_signature_chain(
        self,
        rrsets: List[Tuple[bytes, bytes, int]],
        dnskeys: List[Tuple[bytes, int]],
        ds_records: List[Tuple[bytes, int]],
        zone: str
    ) -> bool:
        """
        验证完整的签名链：RRset -> RRSIG -> DNSKEY -> DS
        
        Args:
            rrsets: [(rrset_data, rrsig_data, algorithm), ...]
            dnskeys: [(dnskey_data, algorithm), ...]
            ds_records: [(ds_digest, algorithm), ...]
            zone: 域名
            
        Returns:
            整个签名链是否有效
        """
        try:
            # 第 1 步：验证 RRSIG 签名
            print(f"[DNSSEC] Starting signature chain validation for zone: {zone}")
            
            all_signatures_valid = True
            for rrset_data, rrsig_data, algo in rrsets:
                # 尝试用每个 DNSKEY 验证签名
                signature_valid = False
                for dnskey_data, dnskey_algo in dnskeys:
                    if self.validate_rrsig(rrsig_data, rrset_data, dnskey_data, dnskey_algo):
                        signature_valid = True
                        break
                
                if not signature_valid:
                    print(f"[DNSSEC] Failed to verify RRset signature for zone: {zone}")
                    all_signatures_valid = False
            
            if not all_signatures_valid:
                return False
            
            # 第 2 步：验证 DNSKEY 与 DS 记录的链
            print(f"[DNSSEC] RRSIG signatures verified, checking DNSKEY-to-DS chain")
            
            dnskey_chain_valid = False
            for dnskey_data, dnskey_algo in dnskeys:
                for ds_digest, ds_algo in ds_records:
                    # 计算 key tag（用于匹配）
                    key_tag = self._calculate_key_tag(dnskey_data)
                    if self.validate_ds_record(dnskey_data, ds_digest, ds_algo, key_tag):
                        dnskey_chain_valid = True
                        print(f"[DNSSEC] DNSKEY chain validation successful for zone: {zone}")
                        break
                if dnskey_chain_valid:
                    break
            
            if not dnskey_chain_valid and ds_records:
                print(f"[DNSSEC] Failed to validate DNSKEY-to-DS chain for zone: {zone}")
            
            return all_signatures_valid and (dnskey_chain_valid or not ds_records)
            
        except Exception as e:
            print(f"[DNSSEC] Signature chain validation error: {e}")
            return False
    
    def _calculate_key_tag(self, dnskey_data: bytes) -> int:
        """计算 DNSKEY 的 key tag（RFC 4034）"""
        try:
            if len(dnskey_data) < 4:
                return 0
            
            # 跳过前 3 个字节（标志）
            data = dnskey_data[3:]
            
            # 计算校验和
            ac = 0
            for i, byte in enumerate(data):
                if i % 2 == 0:
                    ac += (byte << 8)
                else:
                    ac += byte
            
            ac = (ac >> 16) + (ac & 0xFFFF)
            ac = (ac >> 16) + ac
            key_tag = ac & 0xFFFF
            
            return key_tag
            
        except Exception as e:
            print(f"[DNSSEC] Error calculating key tag: {e}")
            return 0





def min_ttl(records: Iterable) -> int:
    ttls = [int(rr.ttl) for rr in records if hasattr(rr, "ttl")]
    return min(ttls) if ttls else 60


class DNSServer:
    def __init__(
        self,
        host: str,
        port: int,
        upstream: str,
        upstream_port: int,
        config_path: str,
        cache_path: str,
        timeout: float = 4.0,
        dga_detector: Optional[DGAClassifier] = None,
        dga_action: str = "refuse",
        sinkhole_ipv4: str = "0.0.0.0",
        sinkhole_ipv6: str = "::",
        dnssec_enabled: bool = False,
    ) -> None:
        self.host = host
        self.port = port
        self.upstream = upstream
        self.upstream_port = upstream_port
        self.timeout = timeout
        self.local_records = LocalRecords(config_path)
        self.cache = DNSCache(cache_path)
        self.dga_detector = dga_detector
        self.dga_action = dga_action
        self.sinkhole_ipv4 = sinkhole_ipv4
        self.sinkhole_ipv6 = sinkhole_ipv6
        
        # DNSSEC 验证器
        self.dnssec_enabled = dnssec_enabled
        self.dnssec_validator = DNSSECValidator() if dnssec_enabled else None
        self.dnssec_failures: Dict[str, int] = defaultdict(int)  # 追踪 DNSSEC 验证失败
        
        # 启发式预加载参数
        self.preload_enabled = True
        self.time_window = 5.0  # 时间窗口：5秒内的查询视为关联
        self.min_frequency = 3   # 最小频率：需要至少3次才认定为规则
        self.association_rules: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))  # {前置域名: {后续域名: 频率}}
        self.query_history: Deque[Tuple[str, float]] = deque(maxlen=1000)  # 最多保留1000条查询记录
        self.query_lock = threading.Lock()  # 线程锁保护共享数据结构
        self.preload_threads: List[threading.Thread] = []  # 跟踪所有预加载线程

    def serve_forever(self) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.bind((self.host, self.port))
            print(f"DNS server listening on udp://{self.host}:{self.port}")
            print(f"Upstream DNS: {self.upstream}:{self.upstream_port}")
            if self.dga_detector:
                print(
                    "DGA protection enabled:"
                    f" model={self.dga_detector.model_path}"
                    f" threshold={self.dga_detector.threshold}"
                    f" action={self.dga_action}"
                )
            if self.dnssec_enabled:
                print(
                    "DNSSEC validation enabled:"
                    f" validator=DNSSECValidator"
                    f" algorithms=RSA/ECDSA/EdDSA"
                )
            if self.preload_enabled:
                print(
                    "Heuristic preloading enabled:"
                    f" time_window={self.time_window}s"
                    f" min_frequency={self.min_frequency}"
                )
                # 启动关联规则更新线程
                update_thread = threading.Thread(
                    target=self._rule_update_loop,
                    daemon=True
                )
                update_thread.start()
            
            while True:
                data, addr = sock.recvfrom(4096)
                try:
                    response = self.handle_query(data)
                except Exception as exc:
                    print(f"Failed to handle query from {addr}: {exc}")
                    response = self.build_error_response(data, RCODE.SERVFAIL)
                sock.sendto(response, addr)

    def _rule_update_loop(self) -> None:
        """定期更新关联规则的后台线程。"""
        previous_rules = {}  # 追踪上一次的规则状态
        while True:
            try:
                time.sleep(2)  # 每2秒更新一次关联规则
                self._update_association_rules()
                
                # 定期打印关联规则统计信息
                with self.query_lock:
                    if self.association_rules:
                        print(f"[RULES] Found {len(self.association_rules)} prefix domains with {sum(len(v) for v in self.association_rules.values())} associations")
                        # 打印top 5的关联规则
                        all_rules = []
                        for prefix, suffixes in self.association_rules.items():
                            for suffix, freq in suffixes.items():
                                all_rules.append((prefix, suffix, freq))
                        all_rules.sort(key=lambda x: x[2], reverse=True)
                        for prefix, suffix, freq in all_rules[:5]:
                            if freq >= self.min_frequency:
                                print(f"  {prefix} -> {suffix} (freq={freq})")
                        
                        # 【关键】检查是否有新规则或规则频率达到阈值，立即触发预加载
                        for prefix, suffixes in self.association_rules.items():
                            for suffix, freq in suffixes.items():
                                prev_freq = previous_rules.get(prefix, {}).get(suffix, 0)
                                # 规则首次达到最小频率或频率显著增加时触发
                                if (prev_freq < self.min_frequency and freq >= self.min_frequency) or \
                                   (freq >= self.min_frequency and freq > prev_freq + 2):
                                    print(f"[PRELOAD-TRIGGER] New strong rule detected: {prefix} -> {suffix} (freq={prev_freq}→{freq})")
                                    self._preload_domain_safe(suffix, prefix, freq)
                        
                        # 更新上一次的规则状态
                        previous_rules = {
                            prefix: dict(suffixes) 
                            for prefix, suffixes in self.association_rules.items()
                        }
            except Exception as e:
                print(f"Rule update loop error: {e}")
    
    def _preload_domain_safe(self, domain: str, trigger_domain: str, frequency: int) -> None:
        """安全的预加载方法（可在持有锁时调用）。"""
        thread = threading.Thread(
            target=self._preload_domain,
            args=(domain, trigger_domain, frequency),
            daemon=True
        )
        thread.start()
        self.preload_threads.append(thread)

    def handle_query(self, data: bytes) -> bytes:
        request = DNSRecord.parse(data)
        if not request.questions:
            return self.build_error_response(data, RCODE.FORMERR)

        question = request.questions[0]
        name = normalize_name(question.qname)
        rtype = qtype_name(question.qtype)
        print(f"query name={name} type={rtype}")

        dga_response = self.try_dga_block(request, name, rtype)
        if dga_response is not None:
            return dga_response

        if rtype not in SUPPORTED_TYPES:
            return self.forward_to_upstream(data)

        local_answers = self.local_records.lookup(name, rtype)
        if local_answers:
            reply = request.reply()
            reply.header.aa = 1
            reply.header.ra = 1
            for rr in local_answers:
                reply.add_answer(rr)
            # 记录本地解析的查询
            if self.preload_enabled:
                self._record_query(name)
            return reply.pack()

        cached = self.cache.get(name, rtype)
        if cached:
            cached_reply = DNSRecord.parse(cached)
            cached_reply.header.id = request.header.id
            cached_reply.questions = request.questions
            cached_reply.header.ra = 1
            print(f"cache hit name={name} type={rtype}")
            # 记录缓存命中的查询
            if self.preload_enabled:
                self._record_query(name)
            return cached_reply.pack()

        response = self.forward_to_upstream(data)
        upstream_reply = DNSRecord.parse(response)
        
        # DNSSEC 签名验证
        if self.dnssec_enabled:
            dnssec_valid = self._validate_response_dnssec(upstream_reply, name, rtype)
            if not dnssec_valid:
                self.dnssec_failures[name] += 1
                print(f"[DNSSEC] Signature validation failed for {name}, failure count: {self.dnssec_failures[name]}")
                # 可选：返回 SERVFAIL 拒绝无法验证的响应
                # return self.build_error_response(data, RCODE.SERVFAIL)
        
        ttl = min_ttl([*upstream_reply.rr, *upstream_reply.auth, *upstream_reply.ar])
        if upstream_reply.header.rcode == RCODE.NOERROR and ttl > 0:
            self.cache.set(name, rtype, response, ttl)
            print(f"cache store name={name} type={rtype} ttl={ttl}")
        
        # 记录查询并触发启发式预加载
        if self.preload_enabled:
            self._record_query(name)
            self._trigger_heuristic_preload(name)
        
        return response

    def _record_query(self, name: str) -> None:
        """记录查询，用于发现关联规则。"""
        now = time.time()
        with self.query_lock:
            self.query_history.append((name, now))

    def _trigger_heuristic_preload(self, current_name: str) -> None:
        """根据关联规则触发启发式预加载。"""
        now = time.time()
        with self.query_lock:
            # 查找关联的后续域名
            if current_name in self.association_rules:
                associated_domains = self.association_rules[current_name]
                # 按频率排序，取出最高频的关联域名
                if associated_domains:
                    # 筛选出达到最小频率的关联域名
                    strong_rules = [(domain, freq) for domain, freq in associated_domains.items() 
                                  if freq >= self.min_frequency]
                    if strong_rules:
                        strong_rules.sort(key=lambda x: x[1], reverse=True)
                        # 启动后台线程预加载前3个关联域名
                        for domain, freq in strong_rules[:3]:
                            thread = threading.Thread(
                                target=self._preload_domain,
                                args=(domain, current_name, freq),
                                daemon=True
                            )
                            thread.start()
                            self.preload_threads.append(thread)
    
    def _preload_triggered_by_rule(self, prefix_domain: str, suffix_domains: list) -> None:
        """在发现规则时立即触发预加载（关键方法）。"""
        for domain, freq in suffix_domains[:3]:
            if freq >= self.min_frequency:
                thread = threading.Thread(
                    target=self._preload_domain,
                    args=(domain, prefix_domain, freq),
                    daemon=True
                )
                thread.start()
                self.preload_threads.append(thread)

    def _preload_domain(self, domain: str, trigger_domain: str, frequency: int) -> None:
        """后台线程：预加载一个域名到缓存。"""
        try:
            # 检查缓存中是否已有该域名记录
            cached = self.cache.get(domain, "A")
            if cached is not None:
                print(f"preload skipped domain={domain} trigger_by={trigger_domain} reason=already_cached")
                return
            
            # 从上游DNS获取该域名的A记录
            print(f"preload triggered domain={domain} trigger_by={trigger_domain} frequency={frequency}")
            request = DNSRecord.question(domain, "A")
            data = request.pack()
            
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(self.timeout)
                try:
                    sock.sendto(data, (self.upstream, self.upstream_port))
                    response, _ = sock.recvfrom(4096)
                    
                    upstream_reply = DNSRecord.parse(response)
                    ttl = min_ttl([*upstream_reply.rr, *upstream_reply.auth, *upstream_reply.ar])
                    if upstream_reply.header.rcode == RCODE.NOERROR and ttl > 0:
                        self.cache.set(domain, "A", response, ttl)
                        print(f"preload success domain={domain} type=A ttl={ttl} trigger_by={trigger_domain}")
                    else:
                        print(f"preload failed domain={domain} reason=rcode_{upstream_reply.header.rcode}")
                except socket.timeout:
                    print(f"preload timeout domain={domain} timeout={self.timeout}s")
                except Exception as e:
                    print(f"preload error domain={domain} error={type(e).__name__}: {e}")
        except Exception as e:
            print(f"preload thread error: {type(e).__name__}: {e}")

    def _update_association_rules(self) -> None:
        """分析查询历史，更新关联规则。"""
        now = time.time()
        with self.query_lock:
            # 清理过期的历史记录（保留最近10秒的记录用于分析）
            valid_history = [(name, timestamp) for name, timestamp in self.query_history 
                           if now - timestamp < self.time_window * 2]
            self.query_history = deque(valid_history, maxlen=1000)
            
            # 【优化】只分析最近的记录，提高发现速度
            recent_cutoff = now - 10  # 只看最近10秒
            recent_history = [(name, timestamp) for name, timestamp in self.query_history 
                            if timestamp >= recent_cutoff]
            
            # 分析时间窗口内的关联关系
            for i in range(len(recent_history) - 1):
                current_name, current_time = recent_history[i]
                
                # 查看后续的查询
                for j in range(i + 1, len(recent_history)):
                    next_name, next_time = recent_history[j]
                    
                    # 如果在时间窗口内且不是同一个域名
                    if next_time - current_time <= self.time_window and current_name != next_name:
                        self.association_rules[current_name][next_name] += 1
                    elif next_time - current_time > self.time_window:
                        break

    def _validate_response_dnssec(self, reply: DNSRecord, name: str, rtype: str) -> bool:
        """
        验证 DNS 响应的 DNSSEC 签名
        
        Args:
            reply: 上游 DNS 服务器的响应
            name: 查询的域名
            rtype: 查询的资源记录类型
            
        Returns:
            DNSSEC 验证是否成功
        """
        try:
            if not self.dnssec_validator:
                return True  # 禁用时认为验证成功
            
            # 提取 RRSIG 和 DNSKEY 记录
            rrsigs = []
            dnskeys = []
            ds_records = []
            
            # 从权威部分提取记录
            for rr in reply.auth:
                rr_type = qtype_name(rr.rtype)
                if rr_type == "RRSIG":
                    rrsigs.append(rr)
                elif rr_type == "DNSKEY":
                    dnskeys.append(rr)
                elif rr_type == "DS":
                    ds_records.append(rr)
            
            # 如果没有 RRSIG，则无法验证
            if not rrsigs:
                print(f"[DNSSEC] No RRSIG records found for {name}")
                return False  # 严格模式：没有签名则验证失败
            
            # 如果没有 DNSKEY，则无法验证
            if not dnskeys:
                print(f"[DNSSEC] No DNSKEY records found for {name}")
                return False
            
            # 构建 RRset 数据用于验证
            rrsets_to_verify = []
            for rr in reply.rr:
                if qtype_name(rr.rtype) == rtype:
                    # 将 RR 转换为验证格式
                    rrset_data = self._serialize_rrset(reply.rr, rtype)
                    if rrset_data:
                        for rrsig in rrsigs:
                            # 提取 RRSIG 中的签名数据
                            rrsig_data = self._extract_rrsig_signature(rrsig)
                            if rrsig_data:
                                algorithm = self._extract_rrsig_algorithm(rrsig)
                                rrsets_to_verify.append((rrset_data, rrsig_data, algorithm))
            
            if not rrsets_to_verify:
                print(f"[DNSSEC] No RRsets to verify for {name}")
                return False
            
            # 准备 DNSKEY 数据列表
            dnskey_data_list = []
            for dnskey_rr in dnskeys:
                dnskey_data = self._extract_dnskey_data(dnskey_rr)
                algorithm = self._extract_dnskey_algorithm(dnskey_rr)
                if dnskey_data:
                    dnskey_data_list.append((dnskey_data, algorithm))
            
            # 准备 DS 记录列表
            ds_data_list = []
            for ds_rr in ds_records:
                ds_digest = self._extract_ds_digest(ds_rr)
                ds_algo = self._extract_ds_algorithm(ds_rr)
                if ds_digest:
                    ds_data_list.append((ds_digest, ds_algo))
            
            # 验证完整的签名链
            validation_result = self.dnssec_validator.validate_signature_chain(
                rrsets_to_verify,
                dnskey_data_list,
                ds_data_list,
                name
            )
            
            print(f"[DNSSEC] Validation result for {name}: {validation_result}")
            return validation_result
            
        except Exception as e:
            print(f"[DNSSEC] Response validation error for {name}: {e}")
            return False
    
    def _serialize_rrset(self, rrset: List, rtype: str) -> Optional[bytes]:
        """将 RRset 序列化为字节流用于签名验证"""
        try:
            data = b""
            for rr in rrset:
                if qtype_name(rr.rtype) == rtype:
                    # 简化：直接使用 RR 的原始数据
                    data += rr.toZone().encode()
            return data if data else None
        except Exception as e:
            print(f"[DNSSEC] Error serializing RRset: {e}")
            return None
    
    def _extract_rrsig_signature(self, rrsig_rr) -> Optional[bytes]:
        """从 RRSIG 记录提取签名数据"""
        try:
            # RRSIG 格式：Type Covered(2) + Algorithm(1) + Labels(1) + Original TTL(4) + 
            #           Signature Inception(4) + Signature Expiration(4) + Key Tag(2) + Signer Name + Signature
            rrsig_data = str(rrsig_rr.rdata)
            # 这里需要解析 RRSIG 的实际格式
            # 简化版本：返回 RR 数据的最后部分作为签名
            return rrsig_data.encode() if rrsig_data else None
        except Exception as e:
            print(f"[DNSSEC] Error extracting RRSIG signature: {e}")
            return None
    
    def _extract_rrsig_algorithm(self, rrsig_rr) -> int:
        """从 RRSIG 记录提取算法"""
        try:
            rrsig_str = str(rrsig_rr.rdata)
            # RRSIG 的算法通常是第二个字段
            parts = rrsig_str.split()
            if len(parts) >= 2:
                return int(parts[1])
            return DNSSECValidator.RSAKEY_SHA256  # 默认
        except Exception as e:
            print(f"[DNSSEC] Error extracting RRSIG algorithm: {e}")
            return DNSSECValidator.RSAKEY_SHA256
    
    def _extract_dnskey_data(self, dnskey_rr) -> Optional[bytes]:
        """从 DNSKEY 记录提取公钥数据"""
        try:
            dnskey_str = str(dnskey_rr.rdata)
            # DNSKEY 格式：Flags(2) + Protocol(1) + Algorithm(1) + Public Key
            return dnskey_str.encode() if dnskey_str else None
        except Exception as e:
            print(f"[DNSSEC] Error extracting DNSKEY data: {e}")
            return None
    
    def _extract_dnskey_algorithm(self, dnskey_rr) -> int:
        """从 DNSKEY 记录提取算法"""
        try:
            dnskey_str = str(dnskey_rr.rdata)
            # DNSKEY 的算法通常是第三个字段
            parts = dnskey_str.split()
            if len(parts) >= 3:
                return int(parts[2])
            return DNSSECValidator.RSAKEY_SHA256  # 默认
        except Exception as e:
            print(f"[DNSSEC] Error extracting DNSKEY algorithm: {e}")
            return DNSSECValidator.RSAKEY_SHA256
    
    def _extract_ds_digest(self, ds_rr) -> Optional[bytes]:
        """从 DS 记录提取摘要"""
        try:
            ds_str = str(ds_rr.rdata)
            # DS 格式：Key Tag(2) + Algorithm(1) + Digest Type(1) + Digest
            parts = ds_str.split()
            if len(parts) >= 4:
                # 摘要通常是最后一个字段
                digest_hex = parts[3]
                return bytes.fromhex(digest_hex)
            return None
        except Exception as e:
            print(f"[DNSSEC] Error extracting DS digest: {e}")
            return None
    
    def _extract_ds_algorithm(self, ds_rr) -> int:
        """从 DS 记录提取摘要算法"""
        try:
            ds_str = str(ds_rr.rdata)
            # DS 的摘要算法通常是第三个字段
            parts = ds_str.split()
            if len(parts) >= 3:
                return int(parts[2])
            return DNSSECValidator.DS_SHA256  # 默认
        except Exception as e:
            print(f"[DNSSEC] Error extracting DS algorithm: {e}")
            return DNSSECValidator.DS_SHA256

    def try_dga_block(self, request: DNSRecord, name: str, rtype: str) -> Optional[bytes]:
        if self.dga_detector is None:
            return None

        result = self.dga_detector.predict(name)
        print(f"dga score name={name} score={result.score:.4f} malicious={result.is_malicious}")
        if not result.is_malicious:
            return None

        if self.dga_action == "sinkhole":
            return self.build_sinkhole_response(request, name, rtype)

        reply = request.reply()
        reply.header.rcode = RCODE.REFUSED
        reply.header.ra = 1
        print(f"dga blocked name={name} action=refuse")
        return reply.pack()

    def build_sinkhole_response(self, request: DNSRecord, name: str, rtype: str) -> bytes:
        reply = request.reply()
        reply.header.ra = 1
        reply.header.aa = 1

        if rtype == "A":
            reply.add_answer(RR(name + ".", QTYPE.A, rclass=1, ttl=60, rdata=A(self.sinkhole_ipv4)))
        elif rtype == "AAAA":
            reply.add_answer(RR(name + ".", QTYPE.AAAA, rclass=1, ttl=60, rdata=AAAA(self.sinkhole_ipv6)))
        else:
            reply.header.rcode = RCODE.REFUSED
            print(f"dga blocked name={name} action=refuse reason=no_sinkhole_for_{rtype}")
            return reply.pack()

        print(f"dga blocked name={name} action=sinkhole type={rtype}")
        return reply.pack()

    def forward_to_upstream(self, data: bytes) -> bytes:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(self.timeout)
            sock.sendto(data, (self.upstream, self.upstream_port))
            response, _ = sock.recvfrom(4096)
            return response

    def close(self) -> None:
        """关闭服务器并清理资源。"""
        print("Shutting down DNS server...")
        # 等待所有预加载线程完成（最多等待5秒）
        for thread in self.preload_threads:
            if thread.is_alive():
                thread.join(timeout=0.1)
        self.cache.close()
        print("DNS server closed.")

    @staticmethod
    def build_error_response(data: bytes, rcode: int) -> bytes:
        try:
            request = DNSRecord.parse(data)
            reply = request.reply()
            reply.header.rcode = rcode
            reply.header.ra = 1
            return reply.pack()
        except Exception:
            header = DNSHeader(id=0, qr=1, ra=1, rcode=rcode)
            return DNSRecord(header).pack()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="A small recursive DNS server with SQLite cache.")
    parser.add_argument("--host", default="127.0.0.1", help="Bind address, default: 127.0.0.1")
    parser.add_argument("--port", type=int, default=8053, help="UDP port, default: 8053")
    parser.add_argument("--upstream", default="8.8.8.8", help="Upstream recursive DNS server")
    parser.add_argument("--upstream-port", type=int, default=53, help="Upstream DNS port")
    parser.add_argument("--config", default="records.json", help="Local JSON records file")
    parser.add_argument("--cache", default="dns_cache.sqlite3", help="SQLite cache file")
    parser.add_argument("--timeout", type=float, default=4.0, help="Upstream query timeout seconds")
    parser.add_argument("--dga-model", help="Path to trained DGA model joblib file")
    parser.add_argument("--dga-threshold", type=float, default=0.5, help="DGA malicious score threshold")
    parser.add_argument("--dga-action", choices=["refuse", "sinkhole"], default="refuse")
    parser.add_argument("--sinkhole-ipv4", default="0.0.0.0", help="Sinkhole IPv4 address for A queries")
    parser.add_argument("--sinkhole-ipv6", default="::", help="Sinkhole IPv6 address for AAAA queries")
    parser.add_argument("--dnssec", action="store_true", help="Enable DNSSEC signature verification")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    server = DNSServer(
        host=args.host,
        port=args.port,
        upstream=args.upstream,
        upstream_port=args.upstream_port,
        config_path=args.config,
        cache_path=args.cache,
        timeout=args.timeout,
        dga_detector=load_detector(args.dga_model, args.dga_threshold),
        dga_action=args.dga_action,
        sinkhole_ipv4=args.sinkhole_ipv4,
        sinkhole_ipv6=args.sinkhole_ipv6,
        dnssec_enabled=args.dnssec,
    )
    server.serve_forever()


if __name__ == "__main__":
    main()

