import pandas as pd

print("=" * 70)
print("CICIDS2017 TARGET VERIFICATION")
print("=" * 70)

X_train = pd.read_csv("data/features/X_train_scaled.csv")
X_test = pd.read_csv("data/features/X_test_scaled.csv")

y_train = pd.read_csv("data/splits/y_train.csv")
y_test = pd.read_csv("data/splits/y_test.csv")

# Handle possible single-column target
y_train = y_train.iloc[:, 0]
y_test = y_test.iloc[:, 0]

print("\nFeature/target sizes:")
print("X_train:", X_train.shape)
print("y_train:", y_train.shape)
print("X_test :", X_test.shape)
print("y_test :", y_test.shape)

print("\nTraining alignment:", len(X_train) == len(y_train))
print("Testing alignment :", len(X_test) == len(y_test))

print("\nTraining target distribution:")
print(y_train.value_counts())

print("\nTraining target percentages:")
print((y_train.value_counts(normalize=True) * 100).round(3))

print("\nTesting target distribution:")
print(y_test.value_counts())

print("\nTesting target percentages:")
print((y_test.value_counts(normalize=True) * 100).round(3))

print("\nUnique target values:")
print(sorted(y_train.unique()))

print("\n" + "=" * 70)
print("TARGET VERIFICATION COMPLETED")
print("=" * 70)