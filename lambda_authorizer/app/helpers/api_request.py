class APIRequest:
    def __init__(self, event):
        self.event = event
        self.event_version = event.get("version", "2.0")  # 2.0 for http Api gateway
        self.token_data = {}
        self.access_token = None
        self.headers = event.get('headers', {})
        self.auth_header = (
            self.headers.get('Authorization') or 
            self.headers.get('authorization') or 
            event.get('authorizationToken', '')
        )

        if self.event_version == "2.0": # FOR HTTP APIGATEWAY
            self.method_arn = event.get('routeArn', '') # FOR HTTP APIGATEWAY
            self.path = event.get('rawPath','') # FOR HTTP APIGATEWAY
            self.method = event.get('requestContext', {}).get('http', {}).get('method', 'GET') # FOR HTTP APIGATEWAY
            # self.auth_header = self.headers.get('Authorization', self.headers.get('authorization', ''))
        else:
            self.method_arn = event.get('methodArn', '')
            self.path = event.get('path', '') # FOR REST APIGATEWAY
            self.method = event.get('requestContext', {}).get('httpMethod', 'GET') # FOR REST APIGATEWAY
            # self.auth_header = self.headers.get('authorization', '')
