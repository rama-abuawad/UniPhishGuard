# External Dataset Evaluation

Use this for a dataset that was not used for training or threshold tuning.

## CSV Format

Supported formats:

```csv
text,label
"Email text here",phishing
"Legitimate message here",legitimate
```

or:

```csv
subject,body,label
"Subject","Body text",0
"Subject","Body text",1
```

Labels can be `phishing`, `legitimate`, `1`, or `0`.

## Run

```powershell
cd backend
python evaluate_external_dataset.py data\external\your_external_dataset.csv
```

Output is saved to:

```text
backend/app/external_evaluations/
```

## Metrics

The script reports precision, recall, F1, false-positive rate, false-negative rate, ROC-AUC, PR-AUC and confusion matrix.

## Important

Do not use this external dataset for training, threshold tuning or prompt/rule tuning. Keep it untouched until final evaluation.
