from sklearn.datasets import load_breast_cancer
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.neighbors import KNeighborsClassifier
from sklearn.ensemble import RandomForestClassifier  # example model
import pandas as pd
import numpy as np


data = pd.read_csv("/home/pythonic/Desktop/FYP/project/learn_bpf/extract_sysCalls_to_map/dataset/parsing_data/final_combined_dataset.csv")
print(data.head())
X = data.drop("LABEL", axis=1)  # replace with your target column name
y = data["LABEL"]


X_train, X_test, y_train,y_test = train_test_split(X,y, test_size=0.2, random_state=42)



scaler = StandardScaler()

X_train_scale = scaler.fit_transform(X_train)
X_test_scale = scaler.transform(X_test)


from imblearn.over_sampling import SMOTE

smote = SMOTE(random_state=42)
X_train_res, y_train_res = smote.fit_resample(X_train_scale, y_train)

RandomForest = RandomForestClassifier(random_state=42)
RandomForest.fit(X_train_res, y_train_res)
print(RandomForest.score(X_test_scale, y_test))












from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report, roc_auc_score
)
import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
import numpy as np

# -------------------------------
# 1. Predictions
# -------------------------------
y_pred = RandomForest.predict(X_test_scale)

# ROC-AUC if probabilities are available
y_proba = None
if hasattr(RandomForest, "predict_proba"):
    y_proba = RandomForest.predict_proba(X_test_scale)[:, 1]  # positive class probability

# -------------------------------
# 2. Basic Classification Metrics
# -------------------------------
acc = accuracy_score(y_test, y_pred)
prec = precision_score(y_test, y_pred, zero_division=0)
rec = recall_score(y_test, y_pred, zero_division=0)
f1 = f1_score(y_test, y_pred, zero_division=0)

print("===== Classification Metrics =====")
print(f"Accuracy : {acc:.4f}")
print(f"Precision: {prec:.4f}")
print(f"Recall   : {rec:.4f}")
print(f"F1-score : {f1:.4f}")

if y_proba is not None:
    auc = roc_auc_score(y_test, y_proba)
    print(f"ROC-AUC  : {auc:.4f}")

# -------------------------------
# 3. Confusion Matrix
# -------------------------------
cm = confusion_matrix(y_test, y_pred)
plt.figure(figsize=(5,4))
sns.heatmap(cm, annot=True, fmt="d", cmap="Blues")
plt.xlabel("Predicted")
plt.ylabel("Actual")
plt.title("Confusion Matrix")
plt.show()

# -------------------------------
# 4. Detailed Classification Report
# -------------------------------
print("\n===== Detailed Classification Report =====")
print(classification_report(y_test, y_pred, zero_division=0))

# -------------------------------
# 5. Feature Importances
# -------------------------------
# Keep feature names from original DataFrame
feature_names = X_train.columns  

fi = RandomForest.feature_importances_

# Create DataFrame and sort
fi_df = pd.DataFrame({
    "Feature": feature_names,
    "Importance": fi
}).sort_values(by="Importance", ascending=False)

# Print nicely
print("\n===== Feature Importances =====")
for idx, row in fi_df.iterrows():
    print(f"{row['Feature']}: {row['Importance']:.4f}")

# Plot as horizontal bar chart (warning-free)
plt.figure(figsize=(10,6))
sns.barplot(
    x="Importance",
    y="Feature",
    data=fi_df,
    color="mediumslateblue"  # single color avoids FutureWarning
)
plt.title("Feature Importances")
plt.tight_layout()
plt.show()
