import pandas as pd
import hashlib

print("=" * 70)
print("CICIDS2017 TRAIN/TEST OVERLAP ANALYSIS")
print("=" * 70)

TRAIN_X = "data/splits/X_train.csv"
TEST_X = "data/splits/X_test.csv"
TRAIN_Y = "data/splits/y_train.csv"
TEST_Y = "data/splits/y_test.csv"

print("\nLoading data...")

X_train = pd.read_csv(TRAIN_X)
X_test = pd.read_csv(TEST_X)
y_train = pd.read_csv(TRAIN_Y).iloc[:, 0]
y_test = pd.read_csv(TEST_Y).iloc[:, 0]

print("X_train:", X_train.shape)
print("X_test :", X_test.shape)

# --------------------------------------------------
# Create hashes
# --------------------------------------------------

print("\nCreating row hashes...")

train_hashes = X_train.astype(str).agg("|".join, axis=1).apply(
    lambda x: hashlib.md5(x.encode()).hexdigest()
)

test_hashes = X_test.astype(str).agg("|".join, axis=1).apply(
    lambda x: hashlib.md5(x.encode()).hexdigest()
)

train_hash_to_index = {}

for i, h in enumerate(train_hashes):
    train_hash_to_index.setdefault(h, []).append(i)

overlap_hashes = set(train_hashes) & set(test_hashes)

print("\nOverlapping unique feature vectors:", len(overlap_hashes))

# --------------------------------------------------
# Analyze labels
# --------------------------------------------------

same_label = 0
conflicting_label = 0

examples = []

for h in overlap_hashes:

    train_indices = train_hash_to_index[h]

    test_indices = [
        i for i, value in enumerate(test_hashes)
        if value == h
    ]

    train_labels = set(y_train.iloc[train_indices])
    test_labels = set(y_test.iloc[test_indices])

    if train_labels == test_labels:
        same_label += 1
    else:
        conflicting_label += 1

    if len(examples) < 10:
        examples.append({
            "hash": h,
            "train_indices": train_indices,
            "test_indices": test_indices,
            "train_labels": list(train_labels),
            "test_labels": list(test_labels)
        })

print("\n" + "=" * 70)
print("OVERLAP LABEL ANALYSIS")
print("=" * 70)

print("Same-label overlaps      :", same_label)
print("Conflicting-label overlaps:", conflicting_label)

# --------------------------------------------------
# Print examples
# --------------------------------------------------

print("\n" + "=" * 70)
print("FIRST OVERLAPPING EXAMPLES")
print("=" * 70)

for i, example in enumerate(examples, 1):

    print(f"\nExample {i}")
    print("-" * 50)

    print("Train indices :", example["train_indices"])
    print("Test indices  :", example["test_indices"])

    print("Train labels  :", example["train_labels"])
    print("Test labels   :", example["test_labels"])

# --------------------------------------------------
# Label distribution of overlapping rows
# --------------------------------------------------

overlap_train_labels = []
overlap_test_labels = []

for h in overlap_hashes:

    train_indices = train_hash_to_index[h]

    test_indices = [
        i for i, value in enumerate(test_hashes)
        if value == h
    ]

    overlap_train_labels.extend(
        y_train.iloc[train_indices].tolist()
    )

    overlap_test_labels.extend(
        y_test.iloc[test_indices].tolist()
    )

print("\n" + "=" * 70)
print("OVERLAPPING LABEL DISTRIBUTION")
print("=" * 70)

print("\nTraining labels among overlaps:")
print(pd.Series(overlap_train_labels).value_counts())

print("\nTesting labels among overlaps:")
print(pd.Series(overlap_test_labels).value_counts())

print("\n" + "=" * 70)
print("OVERLAP ANALYSIS COMPLETED")
print("=" * 70)