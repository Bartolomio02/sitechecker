import re
import json
from selenium import webdriver
from selenium.webdriver.chrome.options import Options

def scan_domains(site):
    options = Options()
    # options.binary_location = "/usr/bin/firefox"
    options.add_argument('--headless')
    options.add_argument('--disable-dev-shm-usage')
    options.add_argument('--no-sandbox')

    driver = webdriver.Chrome('static/chromedriver', options=options)
    # driver = webdriver.Chrome('static/chromedriver_linux', options=options)
    # driver = webdriver.Firefox('/usr/local/bin/')
    # driver.set_page_load_timeout(20)
    #driver.implicitly_wait(1)
    driver.get(site)
    html = driver.page_source
    driver.quit()
    #print(html)

    myArray = []
    myArrayDash = []
    myArrayDash2 = []
    mySetDash = ()

    result = re.findall(r'(src=\'|src="|href=")((http|//).*?)"', html)
    for r in result:
        #print(r[1])
        #print(r)
        myArray.append(r[1])
        for i in myArray:
            index = i.split('//'[1])
            #print(index)
            index_clear = index[2].split('?')
            #print(index_clear[0], 'index_clear')
            myArrayDash.append(index_clear[0])
            #myArrayDash.append(index[2])
            #print(index[2])
    #print(myArrayDash)
    mySetDash = set(myArrayDash)

    response = []
    for i in mySetDash:
        if not i in response:
            response.append(i)

    return response


    # for i in mySetDash:
    #     print(i)

# result = scan_domains('https://www.i.ua/')
# for i, v in enumerate(result):
#     print(i, v)
