# UniPhishGuard Training Dataset Card

## Summary

- **Name:** UniPhishGuard attributed email-text dataset v3
- **File:** `training_dataset.csv`
- **Purpose:** Train and evaluate the English-language TF-IDF and Logistic Regression component used by UniPhishGuard.
- **Records:** 25,821 after preparation-time exact deduplication.
- **Class balance:** 24,231 legitimate and 1,590 phishing messages.
- **Columns:** `label`, `text`, `source`, `template_id`, `is_synthetic`, `split`.
- **Active indicators:** URLs, email addresses, and IP addresses are replaced with `URL`, `EMAIL`, and `IP_ADDRESS` tokens.

## Sources and licences

### Phishing messages

The real phishing examples come from Jose Nazario's hand-screened Phishing Corpus. The corpus README states that it is representative of one personal inbox, may contain classification errors, and is licensed under Creative Commons Attribution 4.0 International.

- Source: <https://monkey.org/~jose/phishing/>
- Licence: <https://monkey.org/~jose/phishing/LICENSE.txt>
- Attribution: Jose Nazario, *The Phishing Corpus*.
- Included years: 2015, 2016, 2018, 2020, and 2025.
- Included after parsing and deduplication: 1,550 messages.

The 2025 messages are reserved for testing. They are not used for training or validation.

### Legitimate messages

Legitimate messages come from the CC BY 4.0 Figshare release *Curated Dataset - Phishing Email*, version 2. Only rows labelled `0` (ham/non-spam) are included. Rows labelled as spam are excluded because ordinary spam and advertising are not equivalent to phishing.

- Dataset page: <https://figshare.com/articles/dataset/Curated_Dataset_-_Phishing_Email/24899952>
- DOI: <https://doi.org/10.6084/m9.figshare.24899952.v2>
- Release licence: Creative Commons Attribution 4.0 International.
- Citation requested by the release: A. I. Champa, M. F. Rabbi, and M. F. Zibran, “Curated datasets and feature analysis for phishing email detection with machine learning,” ICMI, 2024.

Included after preparation and deduplication:

- CEAS-08 ham: 9,951 messages.
- Enron ham: 7,842 messages.
- SpamAssassin ham: 3,998 messages.
- Ling-Spam ham: 2,400 messages.

The original Apache SpamAssassin corpus notes that copyright in individual message text remains with the original senders. This derivative dataset should therefore retain this source notice and attribution. The Enron corpus also contains real workplace correspondence and should be handled with sensitivity despite its public research availability.

### Project hard cases

The training split includes 80 unique, reviewed examples from the project's earlier university-focused synthetic dataset after exact and template-like deduplication. It contains both legitimate notices and phishing scenarios. These examples are marked `is_synthetic=true` and never appear in validation or testing.

## Labelling and preparation

- Nazario messages are labelled `phishing` based on the source corpus classification.
- Figshare rows labelled `0` are mapped to `legitimate`; rows labelled `1` are not imported.
- Project hard cases retain their reviewed `legitimate` or `phishing` labels.
- HTML is converted to visible text; attachments are not extracted into the text model.
- URLs, addresses, and IPs are defanged before storage.
- Empty and extremely short records are excluded.
- Exact normalized duplicates are removed before writing the final CSV.
- Template fingerprints keep related messages in one split.
- Legitimate order confirmations, subscriptions, promotions, password resets, and shipment notices are prioritized as training hard negatives.

## Splits

The declared source-aware and time-aware split contains:

- Training: 18,462 messages — 17,572 legitimate and 890 phishing.
- Validation: 3,547 messages — 3,293 legitimate and 254 phishing.
- Testing: 3,812 messages — 3,366 legitimate and 446 phishing.
- Group leakage check: passed.
- Test phishing source: Nazario 2025 only.
- Related normalized groups do not cross partitions.

The validation set selects the phishing decision threshold. The test set is evaluated once after selection and is not used to fit model weights or choose the threshold.

## Saved evaluation

The saved model uses a threshold of 0.50 selected from the validation set under the documented recall/false-positive policy. On the time-separated test split it records:

- Accuracy: 98.03%.
- Phishing precision: 98.69%.
- Phishing recall: 84.30%.
- Phishing F1: 90.93%.
- False-positive rate: 0.15% — 5 of 3,366 legitimate messages.
- False-negative rate: 15.70% — 70 of 446 phishing messages.
- ROC-AUC: 99.82%.
- PR-AUC: 99.07%.

These are text-model metrics, not end-to-end detector metrics. UniPhishGuard also analyzes sender authentication, sender and Reply-To relationships, URLs, attachments, QR codes, and organization-specific signals. No metric guarantees correct predictions on every future email.

## Coverage and limitations

- The corpus is primarily English.
- Arabic and mixed Arabic-English performance has not been evaluated.
- Public sources are imperfect and may contain labelling errors.
- Historical corpora do not represent every modern campaign.
- The real phishing source reflects one collector's inbox and is not globally representative.
- The text model cannot verify sender identity, destination safety, or attachment contents by itself.
- The independent 2,000-message synthetic validation dataset tested during development was useful for finding short-message weaknesses, but its generated distribution differs substantially from real mail and is not included in the saved headline metrics.
- Model probabilities are evidence, not proof.

## Intended uses

- University research and controlled demonstrations.
- A transparent baseline using word and character TF-IDF with calibrated Logistic Regression.
- One signal inside UniPhishGuard's rule-based and ML-assisted assessment.
- Comparison of future model versions using the same untouched test protocol.

## Uses not recommended

- Autonomous email blocking, deletion, or quarantine.
- Treating all spam as phishing.
- Automatic retraining from unreviewed scan history or user feedback.
- Claims of perfect accuracy, zero false positives, or zero false negatives.
- Arabic or multilingual performance claims without separate evaluation.

## Reproduction

`prepare_training_data.py` creates the final CSV from locally downloaded source files. `train_model.py` performs group-aware calibration, trains the model, selects a validation threshold, evaluates the held-out test split, and writes model, metrics, and integrity artifacts together.
