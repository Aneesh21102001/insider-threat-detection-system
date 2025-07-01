import os
import joblib
import pandas as pd

# Load model and encoders
BASE_DIR = os.path.dirname(__file__)
model = joblib.load(os.path.join(BASE_DIR, 'model.pkl'))
le_user, le_resource, le_action = joblib.load(os.path.join(BASE_DIR, 'encoders.pkl'))

def safe_transform(le, value, field_name):
    try:
        return le.transform([value])[0]
    except ValueError:
        raise ValueError(f"Unknown {field_name}: '{value}'")

def predict_threat(data_dict):
    df = pd.DataFrame([data_dict])
    
    df['user_id'] = df['user_id'].apply(lambda x: safe_transform(le_user, x, 'user_id'))
    df['resource_accessed'] = df['resource_accessed'].apply(lambda x: safe_transform(le_resource, x, 'resource_accessed'))
    df['action'] = df['action'].apply(lambda x: safe_transform(le_action, x, 'action'))

    X = df[['user_id', 'resource_accessed', 'action', 'data_transferred']]
    prediction = model.predict(X)
    return 'malicious' if prediction[0] == 1 else 'normal'
