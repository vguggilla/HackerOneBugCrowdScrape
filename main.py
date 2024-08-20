import requests
import json
import os
from dotenv import load_dotenv

url = 'https://hackerone.com/graphql'

with open('cwes_all.json') as f:
    d = json.load(f)
    cweList = []
    for dic in d:
         cweList.append(dic["id"])

    print(cweList)

operationName = "CweDetailsQuery"
variables = {
    "cwe_id": "cwe-79",
    "product_area": "hackactivity",
    "product_feature": "cwe_discovery"
}
query = """
    query CweDetailsQuery($cwe_id: String!) {
        cwe_entry(cwe_id: $cwe_id) {
            cve_ids
            cwe_description
            cwe_id
            cwe_name
            id
            publicly_disclosed_report_ids
            submission_count
            submission_count_10_weeks_ago
            submission_count_11_weeks_ago
            submission_count_12_weeks_ago
            submission_count_1_week_ago
            submission_count_2_weeks_ago
            submission_count_3_weeks_ago
            submission_count_4_weeks_ago
            submission_count_5_weeks_ago
            submission_count_6_weeks_ago
            submission_count_7_weeks_ago
            submission_count_8_weeks_ago
            submission_count_9_weeks_ago
            submission_count_moving_average_10_weeks_ago
            submission_count_moving_average_11_weeks_ago
            submission_count_moving_average_12_weeks_ago
            submission_count_moving_average_1_week_ago
            submission_count_moving_average_2_weeks_ago
            submission_count_moving_average_3_weeks_ago
            submission_count_moving_average_4_weeks_ago
            submission_count_moving_average_5_weeks_ago
            submission_count_moving_average_6_weeks_ago
            submission_count_moving_average_7_weeks_ago
            submission_count_moving_average_8_weeks_ago
            submission_count_moving_average_9_weeks_ago
            submission_count_remediation_time_1_month
            submission_count_remediation_time_1_quarter
            submission_count_remediation_time_1_week
            submission_count_remediation_time_1_year
            submission_count_remediation_time_1_year_plus
            submission_count_remediation_time_24_hours
            submission_count_remediation_time_48_hours
            submission_count_remediation_time_72_hours
            submission_count_remediation_time_pending
            submission_count_severity_critical
            submission_count_severity_high
            submission_count_severity_low
            submission_count_severity_medium
            submission_count_severity_none
            submission_count_severity_unknown
            submission_count_trailing_12_weeks
            submission_pct_10_weeks_ago
            submission_pct_11_weeks_ago
            submission_pct_12_weeks_ago
            submission_pct_1_week_ago
            submission_pct_2_weeks_ago
            submission_pct_3_weeks_ago
            submission_pct_4_weeks_ago
            submission_pct_5_weeks_ago
            submission_pct_6_weeks_ago
            submission_pct_7_weeks_ago
            submission_pct_8_weeks_ago
            submission_pct_9_weeks_ago
            submission_pct_delta_trailing_12_weeks
            submission_pct_end_date_10_weeks_ago
            submission_pct_end_date_11_weeks_ago
            submission_pct_end_date_12_weeks_ago
            submission_pct_end_date_1_week_ago
            submission_pct_end_date_2_weeks_ago
            submission_pct_end_date_3_weeks_ago
            submission_pct_end_date_4_weeks_ago
            submission_pct_end_date_5_weeks_ago
            submission_pct_end_date_6_weeks_ago
            submission_pct_end_date_7_weeks_ago
            submission_pct_end_date_8_weeks_ago
            submission_pct_end_date_9_weeks_ago
            submission_pct_remediation_time_1_month
            submission_pct_remediation_time_1_quarter
            submission_pct_remediation_time_1_week
            submission_pct_remediation_time_1_year
            submission_pct_remediation_time_1_year_plus
            submission_pct_remediation_time_24_hours
            submission_pct_remediation_time_48_hours
            submission_pct_remediation_time_72_hours
            submission_pct_remediation_time_pending
            submission_pct_severity_critical
            submission_pct_severity_high
            submission_pct_severity_low
            submission_pct_severity_medium
            submission_pct_severity_none
            submission_pct_severity_unknown
            submission_pct_start_date_10_weeks_ago
            submission_pct_start_date_11_weeks_ago
            submission_pct_start_date_12_weeks_ago
            submission_pct_start_date_1_week_ago
            submission_pct_start_date_2_weeks_ago
            submission_pct_start_date_3_weeks_ago
            submission_pct_start_date_4_weeks_ago
            submission_pct_start_date_5_weeks_ago
            submission_pct_start_date_6_weeks_ago
            submission_pct_start_date_7_weeks_ago
            submission_pct_start_date_8_weeks_ago
            submission_pct_start_date_9_weeks_ago
        }
    }
"""

query2 = """
{
   __type(name:"CweEntry") {
      fields {
         name
      }  
   }
}
"""


response = requests.post(url=url, json={"query": query, "variables": variables})
# response = requests.post(url=url, json={"query": query2})
#
print("response status code: ", response.status_code)
if response.status_code == 200:
    print("response : ", response.content)
    data = response.json()
    with open('C:\\Users\\vishr\\PycharmProjects\\HackerOneScrape\\CWEJSON.json', 'w') as f:
        json.dump(data, f)
#     print(response.json()["data"]["__type"]['fields'])
#     for dic in response.json()["data"]["__type"]['fields']:
#         print(dic["name"])



