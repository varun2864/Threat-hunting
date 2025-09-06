#script for training model using a preprocessed CIC-IDS-2018 network capture dataset 

import pandas as pd 
import os
from pathlib import Path
import joblib

data_dir = Path('path/to/datasets')

files = list(data_dir.glob('*.parquet')) #where all parquet files will be stored

dfs = [pd.read_parquet(file) for file in files]

df = pd.concat(dfs, ignore_index = True)

from sklearn.model_selection import train_test_split

X = df.drop('Label', axis = 1)
y = df['Label']

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size = 0.2, random_state = 7)

print("training set size : ", len(X_train))
print("testing set size : ", len(X_test))

from sklearn.ensemble import RandomForestClassifier

model = RandomForestClassifier(n_estimators = 100, random_state = 7, n_jobs = -1)

model.fit(X_train, y_train)

print("training complete")

y_pred = model.predict(X_test)

# Evaluate model's performance
print("\nModel Performance Report:")
print(classification_report(y_test, y_pred))

model_filename = "model.joblib"

joblib.dump(model, model_filename) #save model for future use

print("saved model")

from sklearn.metrics import classification_report

y_pred = model.predict(X_test)

print("predicted labels: ")
print(y_pred[:10])
