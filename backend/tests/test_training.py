from train_model import (
    assert_no_group_leakage,
    choose_threshold,
    dedupe_and_group,
    grouped_split,
    split_dataset,
)


def _rows():
    rows = []
    for label in ("legitimate", "phishing"):
        for template in range(10):
            for variant in range(3):
                rows.append({
                    "label": label,
                    "text": f"{label} template {template} notice number {variant} with stable content words",
                    "source": "test",
                    "template_id": f"{label}-{template}",
                    "is_synthetic": "true",
                })
    return rows


def test_grouped_split_has_no_group_leakage():
    rows, _, near_groups = dedupe_and_group(_rows())
    train, validation, test = grouped_split(rows)
    assert near_groups > 0
    assert_no_group_leakage(train, validation, test)


def test_group_leakage_check_rejects_overlap():
    row = {"group": "shared"}
    try:
        assert_no_group_leakage([row], [row], [])
    except ValueError as error:
        assert "leakage" in str(error).lower()
    else:
        raise AssertionError("Expected group leakage to fail")


def test_threshold_policy_meets_recall_and_reduces_false_positives():
    scores = [0.9, 0.8, 0.7, 0.4, 0.3, 0.1]
    labels = ["phishing", "phishing", "phishing", "legitimate", "legitimate", "legitimate"]
    threshold, candidates = choose_threshold(scores, labels, minimum_recall=2 / 3)
    selected = next(candidate for candidate in candidates if candidate["threshold"] == threshold)
    assert selected["recall"] >= 2 / 3
    assert selected["false_positive_rate"] == 0


def test_declared_splits_are_preserved_without_group_leakage():
    rows = []
    for split in ("training", "validation", "testing"):
        for label in ("legitimate", "phishing"):
            rows.append({
                "label": label,
                "text": f"{split} {label} unique content for the declared split test",
                "source": "test",
                "template_id": f"{split}-{label}",
                "is_synthetic": "false",
                "split": split,
            })
    rows, _, _ = dedupe_and_group(rows)
    training, validation, testing, strategy = split_dataset(rows)
    assert strategy == "declared_source_and_time_aware"
    assert {row["split"] for row in training} == {"training"}
    assert {row["split"] for row in validation} == {"validation"}
    assert {row["split"] for row in testing} == {"testing"}
