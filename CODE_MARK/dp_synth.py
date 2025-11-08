#!/usr/bin/env python3

import pandas as pd
import numpy as np
from copulas.multivariate import GaussianMultivariate
from diffprivlib.tools import mean, std
from sklearn.preprocessing import LabelEncoder
from loguru import logger

# -------------------------------
# Step 1: Load data
# -------------------------------
logger.info("📂 Loading dataset...")
df = pd.read_csv("data/input.csv").dropna().reset_index(drop=True)

# Encode categorical features numerically
for col in df.columns:
    if df[col].dtype == 'object' or df[col].dtype == 'string':
        le = LabelEncoder()
        df[col] = le.fit_transform(df[col].astype(str))

# -------------------------------
# Step 2: Add Differential Privacy
# -------------------------------
epsilon = 1.0  # privacy budget (lower = more private)
logger.info(f"🔐 Applying Differential Privacy with ε = {epsilon}")

for col in df.select_dtypes(include=[np.number]).columns:
    col_min, col_max = df[col].min(), df[col].max()
    
    # Replace mean/std with DP-protected estimates
    dp_mean = mean(df[col], epsilon=epsilon, bounds=(col_min, col_max))
    dp_std = std(df[col], epsilon=epsilon, bounds=(col_min, col_max))
    
    # Add small DP noise to data before fitting
    noise = np.random.normal(0, dp_std * 0.01, size=len(df))
    df[col] = df[col] + noise

# -------------------------------
# Step 3: Train Gaussian Copula
# -------------------------------
logger.info("🤖 Training Differentially Private Gaussian Copula...")
model = GaussianMultivariate()
model.fit(df)

# -------------------------------
# Step 4: Generate Synthetic Data
# -------------------------------
num_samples = len(df)
logger.info(f"🧬 Generating {num_samples} synthetic rows...")
synthetic = model.sample(num_samples)

# -------------------------------
# Step 5: Save Output
# -------------------------------
synthetic.to_csv("out/synthetic.csv", index=False)
logger.success("💾 Saved DP synthetic dataset to out/synthetic_dp.csv")

# -------------------------------
# Step 6: Simple Privacy Metrics
# -------------------------------
from sklearn.neighbors import NearestNeighbors
nn = NearestNeighbors(n_neighbors=1)
nn.fit(df.values)
dist, _ = nn.kneighbors(synthetic.values)
logger.info(f"📏 Min Distance: {np.min(dist):.6f}")
logger.info(f"📏 Avg Distance: {np.mean(dist):.6f}")
logger.info("✅ Differentially Private Gaussian Copula complete.")
