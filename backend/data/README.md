# Model Training Data

The model is trained from two CSV files in this folder.

`training_emails.csv` contains 1000 generated university-style training emails:

- 500 legitimate
- 500 phishing

`phishing_legit_dataset_KD_10000.csv` adds 10000 more labeled emails:

- label `0` = legitimate
- label `1` = phishing

The current model uses:

- TF-IDF text features
- Logistic Regression classifier
- labels: `phishing` and `legitimate`

The first dataset is generated from university-email and phishing-email
templates in `backend/generate_training_data.py`. The second dataset is used to
make the text model less dependent on only our generated examples.

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
