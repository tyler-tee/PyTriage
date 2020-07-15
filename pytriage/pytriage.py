import requests
import typing


class TriageClient:

    def __init__(self, client_id: str, client_secret: str, base_url: str,
                 grant_type: str = 'client_credentials', verify_cert: bool = True):
        """
        :param client_id: ID generated during oauth key generation
        :param client_secret: Secret generated during oauth key generation
        :param base_url: Base server URL for your environment
        :param grant_type: Defaults to client_credentials for now (only v2 option for > operator roles)
        :param verify_cert: Indicate whether SSL verification should be performed
        """

        self.client_id = client_id
        self.client_secret = client_secret
        self.base_url = base_url
        self.base_api = self.base_url + '/api/public/v2/'
        self.grant_type = grant_type
        self.session = requests.session()
        self.session.verify = verify_cert

    def authenticate(self) -> bool:
        """
        Authenticate to the v2 endpoint and retrieve a JWT for subsequent interaction
        :return:
        """
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

    def get_categories(self) -> dict:
        """
        Get all categories currently present in your Triage instance
        :return:
        """
        response = self.session.get(self.base_api + '/categories')

        if response.status_code == 200:
            return response.json()
        else:
            return {'Error Code': response.status_code, 'Error Details': response.json()}

    def get_category_details(self, category_id: str) -> dict:
        """
        Get information for specified category ID; You can find this ID using the 'get_categories' method
        :param category_id:
        :return:
        """
        response = self.session.get(self.base_api + f'/categories/{category_id}')

        if response.status_code == 200:
            return response.json()
        else:
            return {'Error Code': response.status_code, 'Error Details': response.json()}

    def create_category(self, name: str, score: int, color: str, malicious: bool = True) -> bool:
        """
        Create a report category
        :param name: Name of the category
        :param score: Value to add to a reporter's reputation score when a report is processed with this category
        :param color: Hex value used to display category color
        :param malicious: Whether the category should be used to classify malicious reports
        :return:
        """
        payload = {
            'data': {
                'type': 'categories',
                'attributes': {
                    'name': name,
                    'score': score,
                    'color': color,
                    'malicious': malicious
                }
            }
        }

        response = self.session.post(self.base_api + '/categories', json=payload)

        return response.status_code == 201

    def list_reporters(self) -> dict:
        """
        View reporters in your environment and their corresponding details
        :return:
        """
        response = self.session.get(self.base_api + '/reporters')

        if response.status_code == 200:
            return response.json()
        else:
            return {'Error Code': response.status_code, 'Error Details': response.json()}

    def get_reporter(self, reporter_id: str) -> dict:
        """
        View a single reporter and corresponding information based on supplied ID
        :param reporter_id: Unique identifier for the reporter for which you're requesting information
        :return:
        """

        response = self.session.get(self.base_api + f'/reporters/{reporter_id}')

        if response.status_code == 200:
            return response.json()
        else:
            return {'Error Code': response.status_code, 'Error Details': response.json()}

    def update_reporter(self, reporter_id: str, vip_status: bool = False, reporter_score=None) -> bool:
        """
        Update a reporter's score or VIP attributes.
        :param reporter_id: Unique reporter ID
        :param vip_status: Boolean indicating desired VIP status for reporter
        :param reporter_score: Optional - Specify whether you'd like to adjust the reporter score or not
        :return:
        """

        payload = {
            'data': {
                'id': reporter_id,
                'type': 'reporters',
                'attributes': {
                    'vip': vip_status
                }
            }
        }

        if reporter_score:
            payload['data']['attributes']['reporter_score'] = reporter_score

        response = self.session.put(self.base_api + f'/reporters/{reporter_id}', json=payload)

        return response.status_code == 200

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

    def get_report(self, report_id: str) -> dict:
        """
        View a single report and corresponding info by ID
        :param report_id: Property set to the unique identifier for the report
        :return:
        """
        response = self.session.get(self.base_api + f'/reports/{report_id}')

        if response.status_code == 200:
            return response.json()
        else:
            return {'Error Code': response.status_code, 'Error': response.json()}

    def update_report(self, report_id: str, tags: typing.List) -> bool:
        """
        Update the tags for a single report without categorization
        :param report_id: Unique ID for target report
        :param tags: List of tags you'd like applied to target report
        :return:
        """
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

        return response.status_code == 200

    def categorize_report(self, report_id: str, category_id: str, tag_list='', response_id: str = '') -> bool:
        """
        Categorize a single report by ID
        :param report_id: Unique identifier for target report
        :param category_id: Desired category for target report - You can get this with the list_categories method
        :param tag_list: Apply a list of desired tags to target report
        :param response_id: If you'd like to send a response, supply the corresponding ID
        :return:
        """

        data = {'category_id': category_id}

        if response_id:
            data['respond_id'] = response_id
        if tag_list:
            data['categorization_tag_list'] = tag_list

        payload = {'data': data}

        response = self.session.post(self.base_api + f'/reports/{report_id}/categorize', json=payload)

        return response.status_code == 204

    def delete_report(self, report_id: str) -> bool:
        """
        If this has been enabled for your environment, you can delete a single report from Triage
        :param report_id: Unique identifier for target report
        :return:
        """
        response = self.session.delete(self.base_api + f'/reports/{report_id}')

        return response.status_code == 204

    def list_rules(self) -> dict:
        """
        View all rules currently defined in your Triage instance
        :return:
        """
        response = self.session.get(self.base_api + '/rules')

        if response.status_code == 200:
            return response.json()
        else:
            return {'Error Code': response.status_code, 'Error Details': response.json()}

    def get_rule(self, rule_id: str) -> dict:
        """
        View a single rule and its corresponding information
        :param rule_id: Unique identifier for target rule
        :return:
        """

        response = self.session.get(self.base_api + f'/rules/{rule_id}')

        if response.status_code == 200:
            return response.json()
        else:
            return {'Error Code': response.status_code, 'Error Details': response.json()}

    def create_rule(self, name: str, priority: int, rule_context: str,
                    description: str, scope: str, content: typing.Union[str, dict],
                    time_to_live: str, share: bool = False) -> bool:
        """
        Create a rule in your instance with supplied parameters
        :param name:
        :param priority:
        :param rule_context:
        :param description:
        :param scope:
        :param content:
        :param time_to_live:
        :param share:
        :return:
        """

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
                    description: str, scope: str, content: typing.Union[str, dict],
                    time_to_live: str, share: bool = False) -> bool:
        """
        Update a single rule in your instance with supplied parameters.
        :param rule_id:
        :param name:
        :param priority:
        :param rule_context:
        :param description:
        :param scope:
        :param content:
        :param time_to_live:
        :param share:
        :return:
        """
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

    def delete_rule(self, rule_id: str) -> bool:
        """
        Delete a single rule from your Triage instance
        :param rule_id: Unique identifier for target rule
        :return:
        """
        response = self.session.delete(self.base_api + f'/rules/{rule_id}')

        return response.status_code == 204

    def indicators_list(self):
        """
        View all Triage Threat indicators defined in your instance
        :return:
        """

        response = self.session.get(self.base_api + '/triage_threat_indicators')

        if response.status_code == 200:
            return response.json()

    def create_indicator(self, threat_level: str, threat_type: str, threat_value: str) -> typing.Tuple[bool, str]:
        """
        Create a Triage Threat Indicator using supplied parameters
        :param threat_level: Level of threat - Must be Malicious, Suspicious, or Benign
        :param threat_type: Type of threat - Must be Sender, Subject, Domain, URL, MD5, or SHA256
        :param threat_value: Value corresponding to type of threat indicated in threat_type
        :return:
        """

        if threat_level not in ('Malicious', 'Suspicious', 'Benign'):
            error = f"Error - Threat level supplied: {threat_level}. Must be Malicious, Suspicious, or Benign."
            return False, error

        if threat_type not in ('Sender', 'Subject', 'Domain', 'URL', 'MD5', 'SHA256'):
            error = f"Error - Type supplied: {threat_type}. Must be Sender, Subject, Domain, URL, MD5, or SHA256."
            return False, error

        payload = {
            'data': {
                'type': 'triage_threat_indicators',
                'attributes': {
                    'threat_level': threat_level,
                    'threat_type': threat_type,
                    'threat_value': threat_value
                }
            }
        }

        response = self.session.post(self.base_api + '/triage_threat_indicators', json=payload)

        return response.status_code == 201, response.text

    def update_indicator(self, indicator_id: str, threat_level: str,
                         threat_type: str, threat_value: str) -> typing.Tuple[bool, str]:
        """
        Update a Triage Threat Indicator using supplied parameters
        :param indicator_id: Property set to unique identifier for the Triage Threat Indicator
        :param threat_level: Level of threat - Must be Malicious, Suspicious, or Benign
        :param threat_type: Type of threat - Must be Sender, Subject, Domain, URL, MD5, or SHA256
        :param threat_value: Value corresponding to type of threat indicated in threat_type
        :return: Boolean indicating success or failure, and a string describing either result
        """

        if threat_level not in ('Malicious', 'Suspicious', 'Benign'):
            error = f"Error - Threat level supplied: {threat_level}. Must be Malicious, Suspicious, or Benign."
            return False, error

        if threat_type not in ('Sender', 'Subject', 'Domain', 'URL', 'MD5', 'SHA256'):
            error = f"Error - Type supplied: {threat_type}. Must be Sender, Subject, Domain, URL, MD5, or SHA256."
            return False, error

        payload = {
            'data': {
                'id': indicator_id,
                'type': 'triage_threat_indicators',
                'attributes': {
                    'threat_level': threat_level,
                    'threat_type': threat_type,
                    'threat_value': threat_value
                }
            }
        }

        response = self.session.put(self.base_api + f'/triage_threat_indicators/{indicator_id}', json=payload)

        return response.status_code == 200, response.text

    def delete_indicator(self, indicator_id: str) -> bool:
        """
        Delete a Triage Threat Indicator
        :param indicator_id: Unique identifier for target indicator
        :return:
        """
        response = self.session.delete(self.base_api + f'/triage_threat_indicators{indicator_id}')

        return response.status_code == 204
