import argparse
import codecs
import csv
import hashlib
import mailbox
import re
import sys
from collections import Counter
from email import policy
from email.header import decode_header, make_header
from email.parser import BytesParser
from pathlib import Path

from app.html_text import visible_html_text
from train_model import template_fingerprint


ROOT = Path(__file__).resolve().parent
csv.field_size_limit(min(sys.maxsize, 10_000_000))
DEFAULT_OUTPUT = ROOT / "data" / "training_dataset.csv"
MAX_TEXT_LENGTH = 80_000
MIN_TEXT_LENGTH = 20
RANDOM_STATE = "uniphishguard-dataset-v3"

# These limits keep the tracked, attributed derivative dataset manageable while
# retaining varied legitimate business mail, mailing-list posts and newsletters.
HAM_SOURCE_LIMITS = {
    "Enron.csv": 8_000,
    "Ling.csv": 2_400,
    "SpamAssasin.csv": 4_000,
    "CEAS_08.csv": 10_000,
}
HAM_SOURCE_NAMES = {
    "Enron.csv": "figshare_enron_ham",
    "Ling.csv": "figshare_ling_ham",
    "SpamAssasin.csv": "figshare_spamassassin_ham",
    "CEAS_08.csv": "figshare_ceas08_ham",
}
PHISHING_YEAR_SPLITS = {
    2015: "training",
    2016: "training",
    2018: "validation",
    2020: "training",
    2025: "testing",
}
SPLIT_PRIORITY = {"training": 0, "validation": 1, "testing": 2}
URL_PATTERN = re.compile(r"(?:https?://|www\.)[^\s<>\"']+", re.IGNORECASE)
EMAIL_PATTERN = re.compile(r"\b[\w.+-]+@[\w.-]+\.[a-z]{2,}\b", re.IGNORECASE)
IP_PATTERN = re.compile(r"(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)")
HARD_LEGITIMATE_TERMS = (
    "account activated",
    "discount",
    "free shipping",
    "gift card",
    "membership",
    "order confirmation",
    "password reset",
    "pre-order",
    "sale ends",
    "shipment confirmation",
    "subscription",
    "thank you for placing your order",
    "thank you for your purchase",
    "your order",
)


def sanitize_text(value: str) -> str:
    """Remove active indicators and personal addresses while preserving wording."""
    value = URL_PATTERN.sub(" URL ", value or "")
    value = EMAIL_PATTERN.sub(" EMAIL ", value)
    value = IP_PATTERN.sub(" IP_ADDRESS ", value)
    return " ".join(value.replace("\x00", " ").split())[:MAX_TEXT_LENGTH]


def decoded_header(message, name: str) -> str:
    value = message.get(name, "")
    try:
        return str(make_header(decode_header(str(value))))
    except (LookupError, UnicodeError):
        return str(value)


def email_body(message) -> str:
    parsed = BytesParser(policy=policy.default).parsebytes(message.as_bytes())
    parts: list[str] = []
    candidates = parsed.walk() if parsed.is_multipart() else [parsed]
    for part in candidates:
        if part.is_multipart() or part.get_content_disposition() == "attachment":
            continue
        content_type = part.get_content_type()
        if content_type not in {"text/plain", "text/html"}:
            continue
        try:
            content = part.get_content()
        except (LookupError, UnicodeError):
            payload = part.get_payload(decode=True) or b""
            charset = part.get_content_charset() or "utf-8"
            try:
                codecs.lookup(charset)
            except LookupError:
                charset = "utf-8"
            content = payload.decode(charset, errors="replace")
        if content_type == "text/html":
            content = visible_html_text(str(content))
        parts.append(str(content))
    return " ".join(parts)


def load_nazario(source_dir: Path) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for path in sorted(source_dir.glob("phishing-*")):
        match = re.fullmatch(r"phishing-(\d{4})", path.name)
        if not match:
            continue
        year = int(match.group(1))
        if year not in PHISHING_YEAR_SPLITS:
            continue
        try:
            messages = mailbox.mbox(path, create=False)
            for message in messages:
                subject = decoded_header(message, "subject")
                if "FOLDER INTERNAL DATA" in subject.upper():
                    continue
                text = sanitize_text(f"{subject} {email_body(message)}")
                if len(text) >= MIN_TEXT_LENGTH:
                    rows.append({
                        "label": "phishing",
                        "text": text,
                        "source": f"nazario_{year}",
                        "is_synthetic": "false",
                        "requested_split": PHISHING_YEAR_SPLITS[year],
                    })
        except (OSError, PermissionError) as error:
            print(f"Skipping unreadable {path.name}: {error}")
    if not rows:
        raise ValueError("No readable Nazario phishing messages were found.")
    return rows


def load_ham_csv(path: Path, source: str) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    with path.open(newline="", encoding="utf-8-sig", errors="replace") as file:
        reader = csv.DictReader(file)
        required = {"body", "label"}
        if not reader.fieldnames or not required.issubset({name.lower() for name in reader.fieldnames}):
            raise ValueError(f"{path.name} does not have the expected body and label columns.")
        for row in reader:
            normalized = {str(key).lower(): value for key, value in row.items()}
            # These source corpora use 0=ham and 1=spam. Spam is deliberately
            # excluded: unwanted advertising is not equivalent to phishing.
            if str(normalized.get("label", "")).strip() != "0":
                continue
            subject = normalized.get("subject") or ""
            body = normalized.get("body") or ""
            text = sanitize_text(f"{subject} {body}")
            if len(text) >= MIN_TEXT_LENGTH:
                is_hard_negative = any(term in text.casefold() for term in HARD_LEGITIMATE_TERMS)
                rows.append({
                    "label": "legitimate",
                    "text": text,
                    "source": source,
                    "is_synthetic": "false",
                    "requested_split": "training" if is_hard_negative else "",
                    "hard_negative": "true" if is_hard_negative else "false",
                })
    return rows


def load_project_hard_cases(path: Path) -> list[dict[str, str]]:
    """Load the project's reviewed university examples retained in Git history."""
    rows: list[dict[str, str]] = []
    with path.open(newline="", encoding="utf-8-sig", errors="replace") as file:
        reader = csv.DictReader(file)
        if not reader.fieldnames or not {"label", "subject", "body"}.issubset(reader.fieldnames):
            raise ValueError("project_hard_cases.csv must contain label, subject and body columns.")
        for row in reader:
            label = (row.get("label") or "").strip().lower()
            if label not in {"legitimate", "phishing"}:
                continue
            text = sanitize_text(f"{row.get('subject') or ''} {row.get('body') or ''}")
            if len(text) >= MIN_TEXT_LENGTH:
                rows.append({
                    "label": label,
                    "text": text,
                    "source": "uniphishguard_reviewed_hard_cases",
                    "is_synthetic": "true",
                    "requested_split": "training",
                })
    return rows


def deterministic_sample(rows: list[dict[str, str]], limit: int) -> list[dict[str, str]]:
    return sorted(
        rows,
        key=lambda row: (
            0 if row.get("hard_negative") == "true" else 1,
            hashlib.sha256(f"{RANDOM_STATE}:{row['source']}:{row['text']}".encode("utf-8")).digest(),
        ),
    )[:limit]


def deduplicate(rows: list[dict[str, str]]) -> tuple[list[dict[str, str]], int]:
    unique: list[dict[str, str]] = []
    seen: dict[str, str] = {}
    duplicates = 0
    for row in rows:
        exact = " ".join(row["text"].casefold().split())
        previous_label = seen.get(exact)
        if previous_label is not None:
            if previous_label != row["label"]:
                raise ValueError("The same normalized email appears with conflicting labels.")
            duplicates += 1
            continue
        seen[exact] = row["label"]
        item = dict(row)
        item["group"] = f"{row['label']}:{template_fingerprint(row['text'])}"
        unique.append(item)
    return unique, duplicates


def assign_splits(rows: list[dict[str, str]]) -> None:
    group_splits: dict[str, str] = {}
    for row in rows:
        requested = row.get("requested_split")
        if not requested:
            bucket = int(hashlib.sha256(row["group"].encode("utf-8")).hexdigest()[:8], 16) % 100
            requested = "training" if bucket < 70 else "validation" if bucket < 85 else "testing"
        current = group_splits.get(row["group"])
        if current is None or SPLIT_PRIORITY[requested] > SPLIT_PRIORITY[current]:
            group_splits[row["group"]] = requested
    for row in rows:
        row["split"] = group_splits[row["group"]]


def prepare(source_dir: Path, output: Path) -> dict:
    rows = load_nazario(source_dir)
    input_counts = Counter(row["source"] for row in rows)
    project_cases = source_dir / "project_hard_cases.csv"
    if project_cases.exists():
        local_rows = load_project_hard_cases(project_cases)
        rows.extend(local_rows)
        input_counts["uniphishguard_reviewed_hard_cases"] += len(local_rows)
    for filename, limit in HAM_SOURCE_LIMITS.items():
        path = source_dir / filename
        if not path.exists():
            raise FileNotFoundError(f"Required licensed source is missing: {path}")
        source = HAM_SOURCE_NAMES[filename]
        sampled = deterministic_sample(load_ham_csv(path, source), limit)
        rows.extend(sampled)
        input_counts[source] += len(sampled)

    rows, duplicates = deduplicate(rows)
    assign_splits(rows)
    rows.sort(key=lambda row: (row["split"], row["label"], row["source"], row["group"], row["text"]))

    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(
            file,
            fieldnames=["label", "text", "source", "template_id", "is_synthetic", "split"],
        )
        writer.writeheader()
        for row in rows:
            writer.writerow({
                "label": row["label"],
                "text": row["text"],
                "source": row["source"],
                "template_id": "",
                "is_synthetic": row["is_synthetic"],
                "split": row["split"],
            })

    return {
        "records": len(rows),
        "exact_duplicates_removed": duplicates,
        "class_balance": dict(Counter(row["label"] for row in rows)),
        "source_counts": dict(sorted(Counter(row["source"] for row in rows).items())),
        "split_counts": {
            split: dict(Counter(row["label"] for row in rows if row["split"] == split))
            for split in ("training", "validation", "testing")
        },
        "input_counts": dict(sorted(input_counts.items())),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Build the attributed UniPhishGuard training dataset.")
    parser.add_argument("source_dir", type=Path, help="Directory containing the downloaded licensed source files.")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    summary = prepare(args.source_dir, args.output)
    for name, value in summary.items():
        print(f"{name}: {value}")


if __name__ == "__main__":
    main()
