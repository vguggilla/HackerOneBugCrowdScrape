import requests
import json
import os
from dotenv import load_dotenv

url = 'https://hackerone.com/graphql'
# body = """
# {
#     "operationName": "CweDetailsQuery",
#     "variables": {
#         "cwe_id": "cwe-269"
#         "product_area": "hackactivity",
#         "product_feature": "cwe_discovery",
#     },
#     "query": "query CweDetailsQuery($cwe_id: String!) {
#         cwe_entry(cwe_id: $cwe_id)
#     }
# }
# """
operationName = "CweDetailsQuery"
variables = """
{
        "cwe_id": "cwe-269"
        "product_area": "hackactivity",
        "product_feature": "cwe_discovery",
    }
"""
query = """query CweDetailsQuery {
        cwe_entry(cwe_id: "cwe-269") {
            id
        }
    }
"""


response = requests.post(url=url, json={"operationName": operationName, "variables": variables, "query": query})
print("response status code: ", response.status_code)
if response.status_code == 200:
    print("response : ", response.content)

