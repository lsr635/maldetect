# Feature-Based Malware Detection

This project implements feature-based malware detection using static features extracted from Windows Portable Executable (PE) files.

The dataset used in this project is the PE Malware Machine Learning Dataset. The dataset contains raw PE files and CSV metadata files such as `samples.csv` and `samples-augmented.csv`.

## Dataset Files

The dataset includes:

```text
samples/
  <sample_id>
  <sample_id>
  ...

samples.csv
samples-augmented.csv
```

The original `samples.csv` file contains 201,549 samples and the following columns:

```text
id, md5, sha1, sha256, total, positives, list, filetype,
submitted, user_id, length, entropy
```

The augmented CSV file contains the same fields plus:

```text
imphash
```

The target label is the `list` column:

```text
Whitelist -> benign
Blacklist -> malware
```

Label distribution in the provided CSV:

```text
Blacklist: 114,737
Whitelist: 86,812
```

## Environment Setup

This project uses Python 3.11.

### Using conda with pip

Create and activate a conda environment:

```bash
conda create -n malware-ml python=3.11 -y
conda activate malware-ml
```

Install the required Python libraries:

```bash
pip install --upgrade pip
pip install -r requirements.txt
```
