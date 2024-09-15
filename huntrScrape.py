import re

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
from bs4 import BeautifulSoup
from bs4.element import Comment
import time
from createHuntrLinkList import listOfLinks
from selenium.webdriver.firefox.options import Options

options = Options()
options.add_argument('--disable-blink-features=AutomationControlled')

# Set up the Chrome WebDriver
service = Service(ChromeDriverManager().install())

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
   h2 = False
   h1_tag = soup.find('h1', string='Proof of Concept')
   if not h1_tag:
      h1_tag = soup.find('h1', string='POC')
   if not h1_tag:
      h1_tag = soup.find('h2', string='Proof of Concept')
      h2 = True
   if not h1_tag:
      h1_tag = soup.find('h2', string='POC')
      h2 = True
   if h1_tag:
      proof_of_concept_section = h1_tag.find_next()

      # Iterate through the following tags until the next heading is reached
      while proof_of_concept_section:
         if proof_of_concept_section.name == 'h1':
            break
         if proof_of_concept_section.name == 'div':
            break
         if h2 and proof_of_concept_section.name == 'h2':
            break
         if proof_of_concept_section.name in ['p', 'pre', 'h2', 'h3']:
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
      if impact_section.name == 'h1':
         break
      if impact_section.name == 'div':  # Replace 'after' with appropriate class
         break
      if impact_section.name in ['p', 'pre', 'h2']:
         impact_text += impact_section.text.strip()
      elif impact_section.name == 'ol':
         for li in impact_section.find_all('li'):
            impact_text += li.text.strip() + '\n'
         impact_text += '\n'  # Add an extra newline after the list
      impact_section = impact_section.find_next()

   return impact_text.strip()


for link in listOfLinks:
   actualLink = "https://huntr.com" + link.get('href')

   try:
      # Navigate to the website
      driver = webdriver.Chrome(service=service)

      driver.get(actualLink)  # Replace with the URL of the website you want to scrape

      print(actualLink)

      # Give the page some time to load
      time.sleep(1)  # Adjust the sleep time as necessary


      soup = BeautifulSoup(driver.page_source, 'html.parser')

      # print(soup)

      title = extract_title(soup).replace(" ", "")
      title = re.sub(r'[\/:*?"<>|]', '', title)

      with (open (f'C:\\Users\\vishr\\PycharmProjects\\HackerOneScrape\\huntrScrapes\\{title}Data.txt', 'w', encoding="utf-8") as f):

         f.write("Title: ")
         f.write(extract_title(soup) + '\n\n')
         f.write("Proof of Concept: \n")
         f.write (extract_proof_of_concept(soup) + '\n\n')
         f.write("Impact: \n")
         f.write(extract_impact(soup) + '\n\n')

         cve_id = soup.find('a', href=lambda x: x and 'https://nvd.nist.gov/vuln/detail/' in x)
         if cve_id:
            cve_id = cve_id.text.strip()
         else:
            cve_id = 'None'

         cve_status = soup.find('span', class_='block capitalize text-white text-opacity-50')
         if cve_status:
            cve_status = cve_status.text.strip()
         else:
            cve_status = 'None'

         vuln_type = soup.find('a', href= lambda x: x and 'https://cwe.mitre.org/data/definitions/' in x)
         if vuln_type:
            vuln_type = vuln_type.text.strip()
         else:
            vuln_type = 'None'

         severity_div = soup.find('div', class_='pt-0.5 text-white text-opacity-50')
         if severity_div:
            severity = severity_div.text.split('(')[0].strip() + ' (' + severity_div.text.split('(')[1].split(')')[0].strip() + ')'
         else:
            f.write("Severity div not found")
            severity = 'None'

         f.write(f"CVE ID: {cve_id}\n")
         f.write(f"Status: {cve_status}\n")
         f.write(f"Vulnerability Type: {vuln_type}\n")
         f.write(f"Severity: {severity}\n")

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

         f.write(f"Attack Vector: {attack_vector}\n")
         f.write(f"Attack Complexity: {attack_complexity}\n")
         f.write(f"Privileges Required: {privileges_required}\n")
         f.write(f"User Interaction: {user_interaction}\n")
         f.write(f"Scope: {scope}\n")
         f.write(f"Confidentiality: {confidentiality}\n")
         f.write(f"Integrity: {integrity}\n")
         f.write(f"Availability: {availability}\n")

         registry = soup.find('span', string='Registry').find_next('span')
         if registry:
            registry = registry.text.strip()
         else:
            registry = 'None'

         affected_version = soup.find('span', string='Affected Version').find_next('p')
         if affected_version:
            affected_version = affected_version.text.strip()
         else:
            affected_version = 'None'

         visibility = soup.find('span', string='Visibility').find_next('span')
         if visibility:
            visibility = visibility.text.strip()
         else:
            visibility = 'None'

         status = soup.find('span', string='Status').find_next('span')
         if status:
            status = status.text.strip()
         else:
            status = 'None'

         disclosure_bounty = soup.find(string='Disclosure Bounty')
         if disclosure_bounty:
            disclosure_bounty = disclosure_bounty.find_next('span').find_next('span')

         if disclosure_bounty:
            disclosure_bounty = disclosure_bounty.text.strip()
         else:
            disclosure_bounty = 'None'

         fix_bounty = soup.find(string='Fix Bounty')
         if fix_bounty:
            fix_bounty = fix_bounty.find_next('span')

         if fix_bounty:
            fix_bounty = fix_bounty.text.strip()
         else:
            fix_bounty = 'None'

         f.write(f"Registry: {registry}\n")
         f.write(f"Affected Version: {affected_version}\n")
         f.write(f"Visibility: {visibility}\n")
         f.write(f"Status: {status}\n")
         f.write(f"Disclosure Bounty: {disclosure_bounty}\n")
         f.write(f"Fix Bounty: {fix_bounty}\n")

         # html = urllib.request.urlopen('https://huntr.com/bounties/1d98bebb-6cf4-46c9-87c3-d3b1972973b5').read()
         # visible_texts = text_from_html(driver.page_source)

         f.close()

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


