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
# Client for v2 endpoint interaction
from pytriage.pytriage import TriageClient

# Instantiate your client
triage_client = TriageClient(<client_id>, <client_secret>, 'https://triageserver.com/')

# Authenticate to retrieve and store a JWT for subsequent requests
triage_client.authenticate()

# Create a new category
triage_client.create_category(name='phishing', score=3, color='#FFFFFF')

# Categorize a report
triage_client.categorize_report(report_id='9999', category_id='4', tag_list=['credential harvesting', 'o365'])

# Client for v1 endpoint interaction
from pytriage.pytriage import TriageClientv1

v1_client = TriageClientv1('joe@test.com', 'secret_token', 'https://triageserver.com')

# Retrieve an attachment
attachment_bytestring = v1_client.get_attachment('attachment_id')

# Download a report preview
v1_client.get_report_preview('9999', 'jpg')

# View all reports from a chosen timeframe
reports = v1_client.get_reports(start_date='2020-07-01', end_date='2020-07-08')
```

## License
[Gnu GPLv3](https://choosealicense.com/licenses/gpl-3.0/)
