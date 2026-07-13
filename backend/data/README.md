# Model Training Data

`training_emails.csv` contains the labeled examples used to train the local
phishing text classifier. It currently has 1000 generated training emails:

- 500 legitimate
- 500 phishing

The current model uses:

- TF-IDF text features
- Logistic Regression classifier
- labels: `phishing` and `legitimate`

The dataset is generated from university-email and phishing-email templates in
`backend/generate_training_data.py`. For real deployment, replace or extend it
with real approved datasets.

Retrain after changing the dataset:

```powershell
cd C:\Users\rama\UniPhishGuard\backend
python train_model.py
```

To rebuild the generated dataset:

```powershell
cd C:\Users\rama\UniPhishGuard\backend
python generate_training_data.py
python train_model.py
```

The trained model is saved to:

```text
backend/app/email_model.joblib
```

Training metrics are saved to:

```text
backend/app/model_metrics.json
```
