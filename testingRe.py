import requests
import re

headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.81 Safari/537.36"}
s = requests.Session()
req_main = s.get("http://www.fplstatistics.co.uk/", headers=headers)

k = re.search(r'"\\x6E\\x61\\x6D\\x65":"(.*?)"', req_main.text).group(1)
v = re.search(r'"\\x76\\x61\\x6C\\x75\\x65":(.*?)}', req_main.text).group(1)

url_json = f"http://www.fplstatistics.co.uk/Home/AjaxPricesIHandler?{k}={v}&pyseltype=0"
req_json = s.get(url_json, headers=headers)
fixtures = [fixture[-1] for fixture in req_json.json()["aaData"]]

for fixture in fixtures:
    print(fixture)