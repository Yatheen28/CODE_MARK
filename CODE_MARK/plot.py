import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
import numpy as np

# ---------------------------
# Step 1: Load data
# ---------------------------
real = pd.read_csv("data/input.csv")
synthetic = pd.read_csv("out/synthetic.csv")

# ---------------------------
# Step 2: Find common numeric columns
# ---------------------------
numeric_real = real.select_dtypes(include=[np.number]).columns
numeric_synth = synthetic.select_dtypes(include=[np.number]).columns
common_cols = list(set(numeric_real).intersection(set(numeric_synth)))

if not common_cols:
    raise ValueError("No common numeric columns found between real and synthetic datasets.")

# ---------------------------
# Step 3: Automatically pick the 'most central' or 'high-risk' column
# (based on lowest mean difference between real and synthetic)
# ---------------------------
mean_diffs = {
    col: abs(real[col].mean() - synthetic[col].mean()) for col in common_cols
    if real[col].notna().any() and synthetic[col].notna().any()
}

# Pick the column with the smallest mean difference
column = min(mean_diffs, key=mean_diffs.get)
print(f"Automatically selected column for comparison: '{column}'")

# ---------------------------
# Step 4: KDE (smooth histogram) comparison
# ---------------------------
plt.figure(figsize=(8, 5))
sns.kdeplot(real[column], label="Real", fill=True, alpha=0.5, color="skyblue")
sns.kdeplot(synthetic[column], label="Synthetic", fill=True, alpha=0.3, color="orange")

plt.title(f"Distribution Comparison: {column}", fontsize=12)
plt.xlabel(column)
plt.ylabel("Density")
plt.legend()
plt.tight_layout()
plt.show()
