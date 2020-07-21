# PyTriage

PyTriage is a Python library for interacting with Cofense Triage's v1 and v2 API's.

## Supported Actions
### Reports
- Categorization
- Deletion
- Tag application
- Metadata retrieval

### Reporters
- Update
- Review
- Metadata retrieval

### Categories
- Creation
- Review
- Metadata retrieval

### Rules
- Creation
- Review
- Update
- Deletion

### Indicators
- Review
- Creation
- Update
- Deletion

## Installation
```python
pip install pytriage
```

## Usage

```python
from pytriage import TriageClient

# Instantiate your client
triage_client = TriageClient(<client_id>, <client_secret>, 'https://triageserver.com/')

# Authenticate to retrieve and store a JWT for subsequent requests
triage_client.authenticate()

# Create a new category
triage_client.create_category(name='phishing', score=3, color='#FFFFFF')

# Categorize a report
triage_client.categorize_report(report_id='9999', category_id='4', tag_list=['credential harvesting', 'o365'])
```

## License
[Gnu GPLv3](https://choosealicense.com/licenses/gpl-3.0/)
