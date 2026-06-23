import pefile
import os
import csv
import json
import random


csv_path = "/home/lsr/pe-machine-learning-dataset/samples.csv"
samples_dir = "/home/lsr/pe-machine-learning-dataset/samples"

json_dir = "output/json_features"
csv_dir = "output/csv_features"

if not os.path.exists(json_dir):
    os.makedirs(json_dir)

if not os.path.exists(csv_dir):
    os.makedirs(csv_dir)


# extract API features from a PE file
def extract_api_features(filepath):
    try:
        pe = pefile.PE(filepath)
    except pefile.PEFormatError:
        return None
    
    # AttributeError: 'SectionStructure' object has no attribute 'next_section_virtual_address'
    except AttributeError:
        return None

    apis = []
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode()
            dll_name = dll_name.lower()

            for imp in entry.imports:
                if imp.name is not None:
                    func_name = imp.name.decode()
                    func_name = func_name.lower()

                    api_string = dll_name + "::" + func_name
                    apis.append(api_string)

    pe.close()
    return apis

# read samples.csv and extract API features for each sample, store in JSON files.

all_samples = []
csv_file = open(csv_path, newline="")
reader = csv.DictReader(csv_file)

count = 0
skipped_missing = 0

for row in reader:
    sample_id = row["id"]
    list_label = row["list"]

    if list_label == "Whitelist":
        label = 0
    else:
        label = 1
#===============================================================
    json_path = os.path.join(json_dir, sample_id + ".json")

    if os.path.exists(json_path):
        all_samples.append([sample_id, json_path, label])
        count += 1
        continue
#===============================================================

    filepath = os.path.join(samples_dir, sample_id)

    if not os.path.exists(filepath):
        skipped_missing += 1
        continue

    apis = extract_api_features(filepath)

    if apis is None:
        skipped_missing += 1
        continue

    data = {"APIs": apis, "Label": label}

    out_file = open(json_path, "w")
    json.dump(data, out_file)
    out_file.close()

    all_samples.append([sample_id, json_path, label])

    count += 1
    if count % 1000 == 0:
        print(f"Processed {count} samples...")

csv_file.close()

print(f"Finished processing {count} samples. Skipped {skipped_missing} samples due to missing files.")


# split train/val/test (80/10/10)
# split benign and malicious samples separately to ensure balanced distribution

benign_samples = []
malicious_samples = []

for sample in all_samples:
    label = sample[2]
    if label == 0:
        benign_samples.append(sample)
    else:
        malicious_samples.append(sample)

random.seed(42)
random.shuffle(benign_samples)
random.shuffle(malicious_samples)

def split_list(samples):
    n = len(samples)
    n_train = int(n * 0.8)
    n_val = int(n * 0.1)

    train = samples[0:n_train]
    val = samples[n_train:n_train + n_val]
    test = samples[n_train + n_val:]
    return train, val, test

benign_train, benign_val, benign_test = split_list(benign_samples)
malicious_train, malicious_val, malicious_test = split_list(malicious_samples)

train_samples = benign_train + malicious_train
val_samples = benign_val + malicious_val
test_samples = benign_test + malicious_test

random.shuffle(train_samples)
random.shuffle(val_samples)
random.shuffle(test_samples)

print("train:", len(train_samples))
print("val:", len(val_samples))
print("test:", len(test_samples))


# write train/val/test samples to CSV files

def write_csv(samples, csv_path_out):
    out_file = open(csv_path_out, "w", newline="")
    writer = csv.writer(out_file)
    writer.writerow(["id", "json_path", "label"])

    for sample in samples:
        writer.writerow(sample)

    out_file.close()

write_csv(train_samples, os.path.join(csv_dir, "train.csv"))
write_csv(val_samples, os.path.join(csv_dir, "val.csv"))
write_csv(test_samples, os.path.join(csv_dir, "test.csv"))

