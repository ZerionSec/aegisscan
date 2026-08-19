# Installation

## Requirements

- Python 3.8 or newer
- `pip`

## Steps

```bash
git clone https://github.com/ZerionSec/aegisscan.git
cd aegisscan
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Verify

```bash
python scanner.py --help
```

## Optional: Development dependencies

```bash
pip install pytest
```
