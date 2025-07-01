import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
import joblib
import os

# Load data
df = pd.read_csv('../../data/raw_logs.csv')

# Encode categorical features
le_user = LabelEncoder()
le_resource = LabelEncoder()
le_action = LabelEncoder()

df['user_id'] = le_user.fit_transform(df['user_id'])
df['resource_accessed'] = le_resource.fit_transform(df['resource_accessed'])
df['action'] = le_action.fit_transform(df['action'])

# Features and labels
X = df[['user_id', 'resource_accessed', 'action', 'data_transferred']]
y = (df['label'] == 'malicious').astype(int)

# Train-test split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)

# Model training
model = RandomForestClassifier()
model.fit(X_train, y_train)

# Save model and encoders
os.makedirs("backend/model", exist_ok=True)
joblib.dump(model, 'backend/model/model.pkl')
joblib.dump((le_user, le_resource, le_action), 'backend/model/encoders.pkl')

print("Model trained and saved.")
