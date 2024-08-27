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
cweListShortened = cweList[900:1000]

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

            vrt_id = "unavailable"
            parent_vrt_id = "unavailable"
            vrt_priority = 0

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

            with open('cwe.json') as f:
                d = json.load(f)
                for item in d["content"]:
                    if item.get("cwe") and item.get("id"):
                        if cwe in item.get("cwe", []):
                            vrt_id = item.get("id", [])

                        for item2 in item.get("children", []):
                            if item2.get("cwe") and item2.get("id"):
                                if cwe in item2.get("cwe", []):
                                    vrt_id = item2.get("id", [])
                                    parent_vrt_id = item.get("id", [])

                                for item3 in item2.get("children", []):
                                    if item3.get("cwe") and item3.get("id"):
                                        if cwe in item3.get("cwe", []):
                                            vrt_id = item3.get("id", [])
                                            parent_vrt_id = item2.get("id", [])

            with open('vulnerability-rating-taxonomy.json') as f:
                d = json.load(f)
                for item in d["content"]:
                    if item.get("id"):
                        if vrt_id in item.get("id", []):
                            if item.get("priority"):
                                vrt_priority = item.get("priority", [])
                            elif item.get("children"):
                                count = 0
                                for item2 in item.get("children", []):
                                    if item2.get("priority"):
                                        vrt_priority += item2.get("priority", [])
                                        count += 1
                                if count != 0:
                                    vrt_priority = vrt_priority / count

                        for item2 in item.get("children", []):
                            if item2.get("id"):
                                if vrt_id in item2.get("id", []):
                                    if item2.get("priority"):
                                        vrt_priority = item2.get("priority", [])
                                    elif item2.get("children"):
                                        count = 0
                                        for item3 in item2.get("children", []):
                                            if item3.get("priority"):
                                                vrt_priority += item3.get("priority", [])
                                                count += 1
                                        if count != 0:
                                            vrt_priority = vrt_priority / count

                                for item3 in item2.get("children", []):
                                    if item3.get("id"):
                                        if vrt_id in item3.get("id", []):
                                            if item3.get("priority"):
                                                vrt_priority = item3.get("priority", [])
                                            elif item3.get("children"):
                                                count = 0
                                                for item4 in item3.get("children", []):
                                                    if item4.get("priority"):
                                                        vrt_priority += item4.get("priority", [])
                                                        count += 1
                                                if count != 0:
                                                    vrt_priority = vrt_priority / count

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
                },
                "bugcrowd": {
                    "collected_date": collected_date,
                    "vrt_id": vrt_id,
                    "parent_vrt_id": parent_vrt_id,
                    "vrt_priority": vrt_priority
                }
            }

        with open(f"C:\\Users\\vishr\\PycharmProjects\\HackerOneScrape\\{cwe}Data.json", 'w') as f:
            json.dump(dictionary, f)
    #     print(response.json()["data"]["__type"]['fields'])
    #     for dic in response.json()["data"]["__type"]['fields']:
    #         print(dic["name"])






