import re

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
from bs4 import BeautifulSoup
from bs4.element import Comment
import urllib.request
import time
import createHuntrLinkList
from createHuntrLinkList import listOfLinks

# Set up the Chrome WebDriver
service = Service(ChromeDriverManager().install())
driver = webdriver.Chrome(service=service)

def tag_visible(element):
   if element.parent.name in ['style', 'script', 'head', 'title', 'meta', '[document]', 'body class', 'li']:
       return False
   if isinstance(element, Comment):
       return False


   return True


def text_from_html(body):
   soup = BeautifulSoup(body, 'html.parser')
   texts = soup.findAll(string=True)
   visible_texts = filter(tag_visible, texts)
   return visible_texts
   # return u" ".join(t.strip() for t in visible_texts)


def extract_title(soup):
   # Extract the title
   title = soup.find('h1', {'id': 'title'}).text.strip()

   return title


def extract_proof_of_concept(soup):
   proof_of_concept_text = ''
   # Find the h1 with text 'Proof of Concept' or 'POC'
   h1_tag = soup.find('h1', string='Proof of Concept')
   if not h1_tag:
      h1_tag = soup.find('h1', string='POC')
   if not h1_tag:
      h1_tag = soup.find('h2', string='Proof of Concept')
   if not h1_tag:
      h1_tag = soup.find('h2', string='POC')
   if h1_tag:
      proof_of_concept_section = h1_tag.find_next()

      # Iterate through the following tags until the next heading is reached
      while proof_of_concept_section:
         if proof_of_concept_section.name.startswith('h'):
            break
         if proof_of_concept_section.name == 'p':
            proof_of_concept_text += proof_of_concept_section.text.strip() + '\n\n'
         elif proof_of_concept_section.name == 'pre':
            proof_of_concept_text += proof_of_concept_section.text.strip() + '\n\n'
         elif proof_of_concept_section.name == 'ol':
            for li in proof_of_concept_section.find_all('li'):
               proof_of_concept_text += li.text.strip() + '\n'
            proof_of_concept_text += '\n'  # Add an extra newline after the list
         proof_of_concept_section = proof_of_concept_section.find_next()

   return proof_of_concept_text.strip()
   # proof_of_concept_text = ''
   # # Extract the h1 title and the following paragraphs and code blocks
   # proof_of_concept_section = soup.find('h1', string='Proof of Concept').find_next()
   # # Initialize an empty string to store the extracted text
   #
   # # Iterate through the following tags until the next heading is reached
   # while proof_of_concept_section and proof_of_concept_section.name != 'h1':
   #    if proof_of_concept_section.name == 'p':
   #       proof_of_concept_text += proof_of_concept_section.text.strip() + '\n\n'
   #    elif proof_of_concept_section.name == 'pre':
   #       proof_of_concept_text += proof_of_concept_section.text.strip() + '\n\n'
   #    proof_of_concept_section = proof_of_concept_section.find_next()
   #
   # return proof_of_concept_text.strip()

def extract_impact(soup):
   impact_text = ''
   # Extract the h1 title and the following paragraphs and code blocks
   impact_section = soup.find('h1', string='Impact').find_next()
   # Initialize an empty string to store the extracted text

   # Iterate through the following tags until the next heading is reached
   while impact_section:
      if impact_section.name.startswith('h'):
         break
      if impact_section.name == 'p':
         impact_text += impact_section.text.strip()
      elif impact_section.name == 'pre':
         impact_text += impact_section.text.strip()
      elif impact_section.name == 'ol':
         for li in impact_section.find_all('li'):
            impact_text += li.text.strip() + '\n'
         impact_text += '\n'  # Add an extra newline after the list
      impact_section = impact_section.find_next()

   return impact_text.strip()


for link in listOfLinks:
   actualLink = "https://huntr.com" + link.get('href')
   print(actualLink)

try:
   # Navigate to the website
   driver.get("https://huntr.com/bounties/1d98bebb-6cf4-46c9-87c3-d3b1972973b5")  # Replace with the URL of the website you want to scrape


   # Give the page some time to load
   time.sleep(3)  # Adjust the sleep time as necessary


   soup = BeautifulSoup(driver.page_source, 'html.parser')

   # print(soup)

   print("Title: ")
   print(extract_title(soup) + '\n')
   print("Proof of Concept: ")
   print (extract_proof_of_concept(soup) + '\n')
   print("Impact")
   print(extract_impact(soup) + '\n')

   cve_id = soup.find('a', href=lambda x: x and 'https://nvd.nist.gov/vuln/detail/' in x).text.strip()

   cve_status = soup.find('span', class_='block capitalize text-white text-opacity-50').text.strip()

   vuln_type = soup.find('a', href= lambda x: x and 'https://cwe.mitre.org/data/definitions/' in x).text.strip()

   severity_div = soup.find('div', class_='pt-0.5 text-white text-opacity-50')
   if severity_div:
      severity = severity_div.text.split('(')[0].strip() + ' (' + severity_div.text.split('(')[1].split(')')[0].strip() + ')'
   else:
      print("Severity div not found")
      severity = None

   print(f"CVE ID: {cve_id}")
   print(f"Status: {cve_status}")
   print(f"Vulnerability Type: {vuln_type}")
   print(f"Severity: {severity}")

   attack_vector = "None"
   attack_complexity = "None"
   privileges_required = "None"
   user_interaction = "None"
   scope = "None"
   confidentiality = "None"
   integrity = "None"
   availability = "None"

   divs = soup.find_all('div', class_='flex flex-row')
   for div in divs:
      span_labels = div.find_all('span')
      if span_labels[0].text.strip() == "Attack vector":
         attack_vector = span_labels[1].text.strip()
      if span_labels[0].text.strip() == "Attack complexity":
         attack_complexity = span_labels[1].text.strip()
      if span_labels[0].text.strip() == "Privileges required":
         privileges_required = span_labels[1].text.strip()
      if span_labels[0].text.strip() == "User interaction":
         user_interaction = span_labels[1].text.strip()
      if span_labels[0].text.strip() == "Scope":
         scope = span_labels[1].text.strip()
      if span_labels[0].text.strip() == "Confidentiality":
         confidentiality = span_labels[1].text.strip()
      if span_labels[0].text.strip() == "Integrity":
         integrity = span_labels[1].text.strip()
      if span_labels[0].text.strip() == "Availability":
         availability = span_labels[1].text.strip()

   print(f"Attack Vector: {attack_vector}")
   print(f"Attack Complexity: {attack_complexity}")
   print(f"Privileges Required: {privileges_required}")
   print(f"User Interaction: {user_interaction}")
   print(f"Scope: {scope}")
   print(f"Confidentiality: {confidentiality}")
   print(f"Integrity: {integrity}")
   print(f"Availability: {availability}")

   registry = soup.find('span', string='Registry').find_next('span').text.strip()
   affected_version = soup.find('span', string='Affected Version').find_next('p').text.strip()
   visibility = soup.find('span', string='Visibility').find_next('span').text.strip()
   status = soup.find('span', string='Status').find_next('span').text.strip()
   disclosure_bounty = soup.find(string='Disclosure Bounty').find_next('span').find_next('span').text.strip()
   fix_bounty = soup.find(string='Fix Bounty').find_next('span').text.strip()

   print(f"Registry: {registry}")
   print(f"Affected Version: {affected_version}")
   print(f"Visibility: {visibility}")
   print(f"Status: {status}")
   print(f"Disclosure Bounty: {disclosure_bounty}")
   print(f"Fix Bounty: {fix_bounty}")

   # html = urllib.request.urlopen('https://huntr.com/bounties/1d98bebb-6cf4-46c9-87c3-d3b1972973b5').read()
   visible_texts = text_from_html(driver.page_source)



   # toPrint = False
   # for t in visible_texts:
   #    if "Proof of Concept" in t:
   #       toPrint = True
   #
   #    if "Occurrences" in t:
   #       toPrint = False
   #
   #    if toPrint:
   #       print(t)
   # for paragraph in soup.findAll('p'):
   #    print(paragraph.text)






finally:
   # Close the WebDriver
   driver.quit()

