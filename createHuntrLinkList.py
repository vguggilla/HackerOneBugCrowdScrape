from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
from bs4 import BeautifulSoup
from bs4.element import Comment
import urllib.request
import time

service = Service(ChromeDriverManager().install())
driver = webdriver.Chrome(service=service)

try:
    # Navigate to the website
    driver.get("https://huntr.com/bounties/hacktivity")

    time.sleep(2)

    soup = BeautifulSoup(driver.page_source, 'html.parser')

    listOfLinks = soup.findAll('a', {'id': 'report-link'})


finally:
   # Close the WebDriver
   driver.quit()