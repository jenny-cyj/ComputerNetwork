import json
from pathlib import Path
from typing import Any, Dict, List

from dnslib import A, AAAA, CNAME, QTYPE, RR

from collections import defaultdict


SUPPORTED_TYPES = {"A", "AAAA", "CNAME"}


def normalize_name(name: str) -> str:
    return str(name).strip().lower().rstrip(".")


class LocalRecords:
    def __init__(self, config_path: str = "records.json") -> None:
        self.config_path = Path(config_path)
        self.records: Dict[str, Dict[str, List[Dict[str, Any]]]] = {}

        # 轮询计数器
        self.round_robin_counter = defaultdict(int)

        self.load()

    def load(self) -> None:
        if not self.config_path.exists():
            self.records = {}
            return
        raw = json.loads(self.config_path.read_text(encoding="utf-8"))
        normalized: Dict[str, Dict[str, List[Dict[str, Any]]]] = {}
        for name, by_type in raw.items():
            normalized_name = normalize_name(name)
            normalized[normalized_name] = {}
            for rtype, values in by_type.items():
                upper_type = rtype.upper()
                if upper_type not in SUPPORTED_TYPES:
                    continue
                normalized[normalized_name][upper_type] = values
        self.records = normalized

    def lookup(self, qname: str, qtype: str) -> List[RR]:
        name = normalize_name(qname)
        requested = qtype.upper()
        by_type = self.records.get(name, {})
        answers: List[RR] = []

        records = by_type.get(requested, [])

        # A记录轮询负载均衡
        if requested == "A" and len(records) > 1:
            idx = self.round_robin_counter[name] % len(records)

            records = records[idx:] + records[:idx]

            self.round_robin_counter[name] += 1

        for item in records:
            answers.append(self._to_rr(name, requested, item))

        if requested != "CNAME":
            for item in by_type.get("CNAME", []):
                answers.append(self._to_rr(name, "CNAME", item))
                target = normalize_name(item["value"])
                target_records = self.records.get(target, {}).get(requested, [])
                for target_item in target_records:
                    answers.append(self._to_rr(target, requested, target_item))

        return answers

    @staticmethod
    def _to_rr(name: str, rtype: str, item: Dict[str, Any]) -> RR:
        ttl = int(item.get("ttl", 300))
        value = str(item["value"])
        if rtype == "A":
            rdata = A(value)
        elif rtype == "AAAA":
            rdata = AAAA(value)
        elif rtype == "CNAME":
            rdata = CNAME(value.rstrip(".") + ".")
        else:
            raise ValueError(f"Unsupported record type: {rtype}")
        return RR(rname=name + ".", rtype=getattr(QTYPE, rtype), rclass=1, ttl=ttl, rdata=rdata)
