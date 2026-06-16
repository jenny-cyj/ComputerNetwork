import csv
import json
import random
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional, Sequence, Tuple

from dga_features import normalize_domain


Dataset = Tuple[List[str], List[int]]

DOMAIN_TOKEN_RE = re.compile(r"^[a-z0-9][a-z0-9.-]*[a-z0-9]$|^[a-z0-9]$")


@dataclass
class DatasetStats:
    path: str
    total_rows: int
    usable_domains: int
    unique_domains: int
    labels: Counter


def clean_domain_token(value: str) -> str:
    domain = normalize_domain(value)
    domain = domain.strip("\"'[]{}(),")
    return domain


def is_domain_like(value: str) -> bool:
    if not value:
        return False
    if value.isdigit():
        return False
    if len(value) > 253:
        return False
    return DOMAIN_TOKEN_RE.match(value) is not None


def pick_domain_from_row(row: Sequence[str]) -> str:
    cleaned = [clean_domain_token(value) for value in row]
    dotted = [value for value in cleaned if "." in value and is_domain_like(value)]
    if dotted:
        return dotted[-1]

    candidates = [value for value in cleaned if is_domain_like(value)]
    return candidates[-1] if candidates else ""


def deduplicate_domains(domains: Iterable[str]) -> List[str]:
    seen = set()
    result = []
    for domain in domains:
        domain = clean_domain_token(domain)
        if is_domain_like(domain) and domain not in seen:
            seen.add(domain)
            result.append(domain)
    return result


def sample_domains(domains: List[str], limit: int, seed: int) -> List[str]:
    if limit <= 0 or len(domains) <= limit:
        return domains
    rng = random.Random(seed)
    return rng.sample(domains, limit)


def sample_labeled_domains(
    domains: List[str], labels: List[int], limit_per_class: int, seed: int
) -> Tuple[List[str], List[int]]:
    """Sample domains separately for each class (0=benign, 1=malicious)"""
    if limit_per_class <= 0:
        return domains, labels
    
    rng = random.Random(seed)
    sampled_domains = []
    sampled_labels = []
    
    # Separate by class
    class_0_indices = [i for i, label in enumerate(labels) if label == 0]
    class_1_indices = [i for i, label in enumerate(labels) if label == 1]
    
    # Sample each class
    if class_0_indices:
        sample_size_0 = min(len(class_0_indices), limit_per_class)
        sampled_0 = rng.sample(class_0_indices, sample_size_0)
        for idx in sampled_0:
            sampled_domains.append(domains[idx])
            sampled_labels.append(labels[idx])
    
    if class_1_indices:
        sample_size_1 = min(len(class_1_indices), limit_per_class)
        sampled_1 = rng.sample(class_1_indices, sample_size_1)
        for idx in sampled_1:
            sampled_domains.append(domains[idx])
            sampled_labels.append(labels[idx])
    
    return sampled_domains, sampled_labels


def read_domain_list(path: str) -> List[str]:
    file_path = Path(path)
    if file_path.suffix.lower() in {".json", ".jsonl", ".ndjson"}:
        domains, _ = read_jsonl_domains(path, domain_col="domain", label_col=None)
        return deduplicate_domains(domains)

    domains: List[str] = []
    with open(path, "r", encoding="utf-8", errors="ignore", newline="") as file:
        sample = file.read(4096)
        file.seek(0)
        if "," in sample:
            reader = csv.reader(file)
            for row in reader:
                domain = pick_domain_from_row(row)
                if domain:
                    domains.append(domain)
        else:
            for line in file:
                if line.startswith("#"):
                    continue
                domain = pick_domain_from_row(line.strip().split())
                if domain:
                    domains.append(domain)
    return deduplicate_domains(domains)


def read_labeled_csv(
    path: str,
    domain_col: str,
    label_col: str,
    malicious_label: str,
    benign_label: str,
) -> Dataset:
    domains: List[str] = []
    labels: List[int] = []
    with open(path, "r", encoding="utf-8", errors="ignore", newline="") as file:
        reader = csv.DictReader(file)
        for row in reader:
            domain = clean_domain_token(row.get(domain_col, ""))
            label = str(row.get(label_col, "")).strip().lower()
            if not is_domain_like(domain):
                continue
            if label == malicious_label.lower():
                domains.append(domain)
                labels.append(1)
            elif label == benign_label.lower():
                domains.append(domain)
                labels.append(0)
    return domains, labels


def read_labeled_jsonl(
    path: str,
    domain_col: str,
    label_col: str,
    malicious_label: str,
    benign_label: str,
) -> Dataset:
    domains, raw_labels = read_jsonl_domains(path, domain_col=domain_col, label_col=label_col)
    final_domains: List[str] = []
    final_labels: List[int] = []
    for domain, label in zip(domains, raw_labels):
        normalized_label = str(label).strip().lower()
        if normalized_label == malicious_label.lower():
            final_domains.append(domain)
            final_labels.append(1)
        elif normalized_label == benign_label.lower():
            final_domains.append(domain)
            final_labels.append(0)
    return final_domains, final_labels


def read_jsonl_domains(path: str, domain_col: str, label_col: Optional[str]) -> Tuple[List[str], List[str]]:
    domains: List[str] = []
    labels: List[str] = []
    with open(path, "r", encoding="utf-8", errors="ignore") as file:
        for line in file:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            domain = clean_domain_token(str(row.get(domain_col, "")))
            if not is_domain_like(domain):
                continue
            domains.append(domain)
            if label_col:
                labels.append(str(row.get(label_col, "")))
    return domains, labels


def inspect_dataset(path: str, domain_col: str = "domain", label_col: str = "threat") -> DatasetStats:
    file_path = Path(path)
    total_rows = 0
    domains: List[str] = []
    labels: Counter = Counter()

    if file_path.suffix.lower() in {".json", ".jsonl", ".ndjson"}:
        with open(path, "r", encoding="utf-8", errors="ignore") as file:
            for line in file:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    continue
                total_rows += 1
                domain = clean_domain_token(str(row.get(domain_col, "")))
                if is_domain_like(domain):
                    domains.append(domain)
                if label_col in row:
                    labels[str(row[label_col]).strip().lower()] += 1
    else:
        with open(path, "r", encoding="utf-8", errors="ignore", newline="") as file:
            reader = csv.reader(file)
            for row in reader:
                total_rows += 1
                domain = pick_domain_from_row(row)
                if domain:
                    domains.append(domain)

    return DatasetStats(
        path=path,
        total_rows=total_rows,
        usable_domains=len(domains),
        unique_domains=len(set(domains)),
        labels=labels,
    )


def load_training_dataset(args) -> Dataset:
    domains: List[str] = []
    labels: List[int] = []

    for path in args.benign or []:
        benign = sample_domains(read_domain_list(path), args.sample_per_class, args.seed)
        domains.extend(benign)
        labels.extend([0] * len(benign))

    for path in args.malicious or []:
        malicious = sample_domains(read_domain_list(path), args.sample_per_class, args.seed)
        domains.extend(malicious)
        labels.extend([1] * len(malicious))

    for path in args.csv or []:
        csv_domains, csv_labels = read_labeled_csv(
            path,
            domain_col=args.domain_col,
            label_col=args.label_col,
            malicious_label=args.malicious_label,
            benign_label=args.benign_label,
        )
        # Apply sampling limit per class for CSV data
        csv_domains, csv_labels = sample_labeled_domains(
            csv_domains, csv_labels, args.sample_per_class, args.seed
        )
        domains.extend(csv_domains)
        labels.extend(csv_labels)

    for path in args.jsonl or []:
        json_domains, json_labels = read_labeled_jsonl(
            path,
            domain_col=args.domain_col,
            label_col=args.label_col,
            malicious_label=args.malicious_label,
            benign_label=args.benign_label,
        )
        # Apply sampling limit per class for JSONL data
        json_domains, json_labels = sample_labeled_domains(
            json_domains, json_labels, args.sample_per_class, args.seed
        )
        domains.extend(json_domains)
        labels.extend(json_labels)

    if not domains:
        raise SystemExit("No training data loaded. Use --benign/--malicious/--csv/--jsonl.")
    return domains, labels
