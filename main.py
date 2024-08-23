from importlib.metadata import distribution

import requests
import json
import os
from dotenv import load_dotenv
from datetime import datetime
from time import sleep

url = 'https://hackerone.com/graphql'

with open('cwes_all.json') as f:
    d = json.load(f)
    cweList = []
    for dic in d:
         cweList.append(dic["id"])

for cwe in cweList:
    sleep(0.1)
    cweLower = cwe.lower()
    operationName = "CweDetailsQuery"
    variables = {
        "cwe_id": cweLower,
        "product_area": "hackactivity",
        "product_feature": "cwe_discovery"
    }
    query = """
        query CweDetailsQuery($cwe_id: String!) {
            cwe_entry(cwe_id: $cwe_id) {
                cwe_id
                cwe_description
                submission_count
                submission_count_trailing_12_weeks

                submission_count_severity_critical
                submission_count_severity_high
                submission_count_severity_low
                submission_count_severity_medium
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

    print("response status code: ", response.status_code)
    if response.status_code == 200:
        data = response.json()
        dictionary = {}
        if data['data'] and data['data']['cwe_entry']:
            print("response : ", response.content)
            cwe_id = data['data']['cwe_entry']['cwe_id'].upper()
            description = data['data']['cwe_entry']['cwe_description']
            collected_date = datetime.today().strftime('%Y-%m-%dT%H:%M:%SZ')
            total_reports = data['data']['cwe_entry']['submission_count']
            unique_reports_last_12_weeks = data['data']['cwe_entry']['submission_count_trailing_12_weeks']
            critical = data['data']['cwe_entry']['submission_count_severity_critical']
            high = data['data']['cwe_entry']['submission_count_severity_high']
            medium = data['data']['cwe_entry']['submission_count_severity_medium']
            low = data['data']['cwe_entry']['submission_count_severity_low']

            with open(f"{cwe}Data.json", 'r') as f:
                d = json.loads(f.read())
                collected_date_formatted = datetime.strptime(collected_date, '%Y-%m-%dT%H:%M:%SZ')
                old_date = d['hackerone']['collected_date']
                old_date = datetime.strptime(old_date, '%Y-%m-%dT%H:%M:%SZ')
                days_past = collected_date_formatted - old_date
                days_past_int = int(days_past.days)
                old_critical = d['hackerone']['severity_distribution']['all_time']['critical']
                old_high = d['hackerone']['severity_distribution']['all_time']['high']
                old_medium = d['hackerone']['severity_distribution']['all_time']['medium']
                old_low = d['hackerone']['severity_distribution']['all_time']['low']


            dictionary = {
                "id": cwe_id,
                "description": description,
                "hackerone":{
                    "collected_date": collected_date,
                    "total_reports": total_reports,
                    "unique_reports_last_12_weeks": unique_reports_last_12_weeks,
                    "severity_distribution":{
                        "all_time":{
                            "critical":critical,
                            "high":high,
                            "medium":medium,
                            "low":low
                        }
                    },
                    "change_distribution":{
                        "days_past": days_past_int,
                        "critical": critical - old_critical,
                        "high": high - old_high,
                        "medium": medium - old_medium,
                        "low": low - old_low
                    }
                }
            }

        with open(f"C:\\Users\\vishr\\PycharmProjects\\HackerOneScrape\\{cwe}Data.json", 'w') as f:
            json.dump(dictionary, f)
    #     print(response.json()["data"]["__type"]['fields'])
    #     for dic in response.json()["data"]["__type"]['fields']:
    #         print(dic["name"])



