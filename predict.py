import pandas as pd
import joblib
import time

# Load the trained Random Forest model
clf = joblib.load('random_forest_model.pkl')

# Load the real-time dataset
df_realtime = pd.read_csv('extracted_data.csv')

# Define features
features = [
    'src_port', 'dst_port', 'length',
    'flags_A', 'flags_ACK', 'flags_Echo Request', 'flags_FA', 'flags_FIN',
    'flags_PA', 'flags_S', 'flags_SA', 'flags_SYN', 'protocol_ICMP',
    'protocol_TCP', 'protocol_UDP'
]

# Select the features from the real-time dataset
X_realtime = df_realtime[features]

# Convert categorical features to one-hot encoding
X_realtime = pd.get_dummies(X_realtime)

# Predict on the real-time dataset
y_pred_realtime = clf.predict(X_realtime)

# Print the predictions
print("Predictions for real-time dataset:")

for index, prediction in enumerate(y_pred_realtime):
    print(f"\nPrediction {index + 1}: {prediction}")
    
    if prediction == 'malicious':
        print("Packet details:")
        print(df_realtime.iloc[index])