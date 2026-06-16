import math
import re
from collections import Counter
from typing import Iterable, List


VOWELS = set("aeiou")
DOMAIN_RE = re.compile(r"^[a-z0-9.-]+$")


def normalize_domain(domain: str) -> str:
    domain = domain.strip().lower().rstrip(".")
    if "://" in domain:
        domain = domain.split("://", 1)[1]
    domain = domain.split("/", 1)[0].split(":", 1)[0]
    return domain


def second_level_domain(domain: str) -> str:
    labels = [label for label in normalize_domain(domain).split(".") if label]
    if len(labels) >= 2:
        return labels[-2]
    return labels[0] if labels else ""


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    total = len(text)
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


def longest_run(text: str, charset: set[str]) -> int:
    longest = 0
    current = 0
    for ch in text:
        if ch in charset:
            current += 1
            longest = max(longest, current)
        else:
            current = 0
    return longest


def ratio(count: int, total: int) -> float:
    return count / total if total else 0.0


def extract_domain_features(domain: str) -> List[float]:
    full = normalize_domain(domain)
    sld = second_level_domain(full)
    labels = [label for label in full.split(".") if label]
    letters = [ch for ch in sld if ch.isalpha()]
    digits = [ch for ch in sld if ch.isdigit()]
    vowels = [ch for ch in letters if ch in VOWELS]
    consonants = [ch for ch in letters if ch not in VOWELS]
    hyphens = sld.count("-")
    total = len(sld)
    unique_chars = len(set(sld))
    tld_len = len(labels[-1]) if labels else 0
    avg_label_len = sum(len(label) for label in labels) / len(labels) if labels else 0.0
    consonant_set = set("bcdfghjklmnpqrstvwxyz")

    return [
        float(len(full)),
        float(total),
        float(len(labels)),
        avg_label_len,
        float(tld_len),
        ratio(len(letters), total),
        ratio(len(digits), total),
        ratio(len(vowels), len(letters)),
        ratio(len(consonants), len(letters)),
        ratio(hyphens, total),
        ratio(unique_chars, total),
        shannon_entropy(sld),
        float(longest_run(sld, set("0123456789"))),
        float(longest_run(sld, consonant_set)),
        float(int(bool(re.search(r"\d", sld)))),
        float(int(DOMAIN_RE.match(full) is not None)),
    ]


class DomainFeatureTransformer:
    """Small sklearn-compatible transformer for handcrafted domain features."""

    def fit(self, domains: Iterable[str], y=None):
        return self

    def transform(self, domains: Iterable[str]):
        import numpy as np

        return np.array([extract_domain_features(domain) for domain in domains], dtype=float)

    def get_params(self, deep: bool = True):
        return {}

    def set_params(self, **params):
        return self
