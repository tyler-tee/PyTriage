import requests
import typing


class TriageClient:

    def __init__(self, client_id: str, client_secret: str, base_url: str,
                 grant_type: str = 'client_credentials', verify_cert: bool = True):
        self.client_id = client_id
        self.client_secret = client_secret
        self.base_url = base_url
        self.base_api = self.base_url + '/api/public/v2/'
        self.grant_type = grant_type
        self.session = requests.session()
        self.session.verify = verify_cert

    def authenticate(self) -> bool:
        payload = {
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'grant_type': self.grant_type
        }

        response = self.session.post(self.base_url + '/oauth/token', json=payload)

        if response.status_code == 200:
            self.session.headers = {
                'Accept': 'application/vnd.api+json',
                'Content-Type': 'application/vnd.api+json',
                'Authorization': f"Bearer {response.json()['access_token']}"
            }

        return response.status_code == 200

    def get_categories(self):

        response = self.session.get(self.base_api + '/categories')

        if response.status_code == 200:
            return response.json()

    def get_category_details(self, category_id: str):

        response = self.session.get(self.base_api + f'/categories/{category_id}')

        if response.status_code == 200:
            return response.json()

    def create_category(self, name: str, score: str, color: str):

        payload = {
            'data': {
                'type': 'categories',
                'attributes': {
                    'name': name,
                    'score': score,
                    'color': color
                }
            }
        }

        response = self.session.post(self.base_api + '/categories', json=payload)

        return response.status_code == 201

    def list_reports(self, location: str = '', headers_contain: str = '', headers_not_contain: str = '') -> dict:
        """
        Get all reports matching supplied parameters; If none are supplied, returns all reports
        :param location: Must be Inbox, Recon, or Processed
        :param headers_contain: Headers contain supplied string value
        :param headers_not_contain: Headers do NOT contain the supplied string value
        :return:
        """
        params = {}

        if location:
            params['filter[location_eq]'] = location

        if headers_contain:
            params['filter[headers_cont'] = headers_contain

        if headers_not_contain:
            params['filter[headers_not_cont'] = headers_not_contain

        response = self.session.get(self.base_api + '/reports', params=params)

        if response.status_code == 200:
            return response.json()
        else:
            return {'Error': response.status_code, 'Error Body': response.json()}

    def get_report(self, report_id: str):

        response = self.session.get(self.base_api + f'/reports/{report_id}')

        if response.status_code == 200:
            return response.json()

    def update_report(self, report_id: str, tags: typing.List):

        payload = {
            'data': {
                'id': report_id,
                'type': 'reports',
                'attributes': {
                    'tags': tags
                }
            }
        }

        response = self.session.put(self.base_api + f'/reports/{report_id}', json=payload)

        if response.status_code == 200:
            return response.json()

    def categorize_report(self, report_id: str, category_id: str, tag_list='', response_id: str = ''):

        data = {'category_id': category_id}

        if response_id:
            data['respond_id'] = response_id
        if tag_list:
            data['categorization_tag_list'] = tag_list

        payload = {'data': data}

        response = self.session.post(self.base_api + f'/reports/{report_id}/categorize', json=payload)

        return response.status_code == 204

    def list_rules(self):

        response = self.session.get(self.base_api + '/rules')

        if response.status_code == 200:
            return response.json()

    def get_rule(self, rule_id: str):

        response = self.session.get(self.base_api + f'/rules/{rule_id}')

        if response.status_code == 200:
            return response.json()

    def create_rule(self, name: str, priority: int, rule_context: str,
                    description: str, scope: str, content: str, time_to_live: str,
                    share: bool = False):

        payload = {
            'data': {
                'type': 'rules',
                'attributes': {
                    'name': name,
                    'description': description,
                    'priority': priority,
                    'scope': scope,
                    'rule_context': rule_context,
                    'active': True,
                    'content': content,
                    'time_to_live': time_to_live,
                    'share_with_cofense': share
                }
            }
        }

        response = self.session.post(self.base_api + '/rules', json=payload)

        return response.status_code == 201

    def update_rule(self, rule_id: str, name: str, priority: int, rule_context: str,
                    description: str, scope: str, content: str, time_to_live: str,
                    share: bool = False):

        payload = {
            'data': {
                'type': 'rules',
                'attributes': {
                    'name': name,
                    'description': description,
                    'priority': priority,
                    'scope': scope,
                    'rule_context': rule_context,
                    'active': True,
                    'content': content,
                    'time_to_live': time_to_live,
                    'share_with_cofense': share
                }
            }
        }

        response = self.session.put(self.base_api + f'/rules/{rule_id}', json=payload)

        return response.status_code == 200


