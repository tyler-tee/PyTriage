# PyTriage

PyTriage is a Python library for interacting with Cofense Triage's v2 API.

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
