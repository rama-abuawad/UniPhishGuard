# UniPhishGuard Model Card

## Model

TF-IDF word and character n-grams with calibrated Logistic Regression.

## Purpose

The model estimates phishing language probability. It is not the whole detector. The final verdict also uses sender, authentication, URL, attachment and university-impersonation checks.

## Training Data

- `backend/data/training_emails.csv`: synthetic university-style examples.
- `backend/data/phishing_legit_dataset_KD_10000.csv`: public-style phishing/legitimate text dataset included with the project.

The training script removes exact duplicates before splitting.

## Evaluation

The script creates train, validation and final test partitions. The validation partition chooses the phishing threshold. The final test partition reports accuracy, precision, recall, F1, false-positive rate, false-negative rate, ROC-AUC, PR-AUC and confusion matrix.

## Limitations

- Current baseline is English-focused.
- Arabic and mixed Arabic-English examples are not yet included.
- Synthetic/template data can overstate accuracy.
- Results should be validated with ADU-approved independent email examples before production use.

## Misuse Risks

- Users may over-trust a low score.
- Attackers may write around obvious phishing phrases.
- A compromised trusted account can still send malicious email.

## Safe Use

Use the score breakdown and strongest reasons together. Do not treat the AI probability as the final phishing risk by itself.
