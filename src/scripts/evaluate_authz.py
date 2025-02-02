import json
import os

import requests

import dotenv

dotenv.load_dotenv('../.env')

url = "http://localhost:8080/admin/realms/customer-1/clients/6d43e70c-51da-4e28-b408-aead11131317/authz/resource-server/policy/evaluate"

payload = {"roleIds":[],"userId":"53f8d887-8c9a-441b-aa69-10ff444d1fcf","resources":[{"name":"/organizations/{org_id}/extension/key-id","owner":{"id":"b3176d46-ac59-45f2-ab41-554c1ddccd78","name":"empower"},"ownerManagedAccess":False,"attributes":{},"_id":"022ffee2-3dc4-4b79-a712-bf2a64dbc781","uris":["/organizations/{org_id}/extension/key-id"],"scopes":[{"id":"a779805d-00b2-456e-8383-f34032abfc60","name":"GET"}]}],"entitlements":False,"context":{"attributes":{}}}

payload['context'] = {
    "attributes": {
      "org_id": "default"
    }
  }

KC_UN = os.getenv('KC_UN')
KC_PASS = os.getenv('KC_PASSWORD')
KC_REALM = os.getenv('KC_REALM')
def get_admin_token():
    """Obtain an admin token from Keycloak."""
    try:
        response = requests.post(
            f"http://localhost:8080/realms/{KC_REALM}/protocol/openid-connect/token",
            data={
                "grant_type": "password",
                "client_id": "admin-cli",
                "username": KC_UN,
                "password": KC_PASS,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        response.raise_for_status()
        return response.json().get("access_token")
    except requests.RequestException as e:
        raise Exception(f"Failed to get admin token: {str(e)}")

headers = {
    'Accept-Language': 'en-GB,en-US;q=0.9,en;q=0.8',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive',
    'Cookie': 'ajs_anonymous_id=57b4f53c-0cf6-4c79-a7a0-a06a0ba92363; rl_page_init_referrer=RudderEncrypt%3AU2FsdGVkX1%2BkST7SXigzKK3BCXoUmQA1MxVGL0JJreM%3D; rl_page_init_referring_domain=RudderEncrypt%3AU2FsdGVkX1%2Bkj9YmqmTb%2B54TaK20xGPLbZPrPWliMyQ%3D; rl_anonymous_id=RudderEncrypt%3AU2FsdGVkX1%2BxhV1qVsuPiQktOWHTNjVuUoLxnfGfZzAV0X1l6WHINA30EBSqv8lR%2Bbv6lfhwOZbEXjWHTTKnpQ%3D%3D; rl_user_id=RudderEncrypt%3AU2FsdGVkX1%2B68uK8LnAJfP4tsFjB2Tc5WWIZY%2F2ZbKQp7xmISpsOccTo7GdleeDLd6W7%2Bl9ErV4gqvcs8l%2B7%2F9SBrznjJ5DDl8XbiKHNf1e7IdfDTLi3eusZp4YWFifHc6q2TuSi%2FO2mZk0GjNVlvBUQSrhYKY2HVkHEwQXSxP4%3D; rl_trait=RudderEncrypt%3AU2FsdGVkX1%2B2WhhxWQ65qsN2A3nBxqyoZX9eeL64bUEXrVlqkWoSWLBaeN4Ne6kq3LyyF9GcwyhJPf6e%2BjT%2F5QeJHc395UNrXCy%2BSimn770ydXnP16gWzmJe6CEnT%2F18HLjZJW2WrnYx%2FE24ykFTvA%3D%3D; rl_session=RudderEncrypt%3AU2FsdGVkX1%2FHQZp3quRhchPjiMZ5EtzSZrT06ZnUHbEXTPjDGdg661PxGcod4Rq%2FhwRM05gQOSF9Y8dU4Ywh1xfs8aJFN6iv1QP6fzj6YSd77kTQc1AZwHZ88OG05XHpYvquBNy6T5at66e9pzzwRA%3D%3D; ph_phc_4URIAm1uYfJO7j8kWSe0J8lc8IqnstRLS7Jx8NcakHo_posthog=%7B%22distinct_id%22%3A%2282177ebef8711053dac6f1fbec3475a95de3bd0ba7a550e404bf3bb683b1ff0f%232e43609f-3f3c-4647-9f1f-222720a79bc9%22%2C%22%24sesid%22%3A%5B1725247589653%2C%220191b0c5-0d16-709c-9838-15ea0389feb4%22%2C1725247589653%5D%2C%22%24epp%22%3Atrue%7D; Pycharm-9fdd39f7=ca5268db-202f-419a-9b45-3dcb1d9a0be3; ab.storage.deviceId.f9c2b69f-2136-44e0-a55a-dff72d99aa19=g%3ANyTkA6WraVWhCvrFbhXi8kxHtel1%7Ce%3Aundefined%7Cc%3A1732999749966%7Cl%3A1732999749966; ab.storage.sessionId.f9c2b69f-2136-44e0-a55a-dff72d99aa19=g%3A9251f75d-677a-dc59-6dd1-373125d2245e%7Ce%3A1733001549975%7Cc%3A1732999749977%7Cl%3A1732999749977; csrftoken=eGKOC2D3gmR07TuMOxSsdp5JXAenvg7H',
    'Origin': 'http://localhost:8080',
    'Pragma': 'no-cache',
    'Sec-Fetch-Dest': 'empty',
    'Sec-Fetch-Mode': 'cors',
    'Sec-Fetch-Site': 'same-origin',
    'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
    'accept': 'application/json, text/plain, */*',
    'authorization': f'Bearer {get_admin_token()}',
    'content-type': 'application/json',
    'sec-ch-ua': '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"macOS"'
}

response = requests.request("POST", url, headers=headers, data=json.dumps(payload))
print(response)
