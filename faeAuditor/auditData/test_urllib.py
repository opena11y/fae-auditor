#Used to make requests
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
import ssl

urls = ['https://www.duke.edu', 'https://www.bc.edu/bc-web/schools/carroll-school.html', 'https://www.clemson.edu/science/']

ctx                = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
ctx.check_hostname = False
ctx.verify_mode    = ssl.CERT_NONE

hdr = { 'User-Agent' : 'Mozilla/5.0 (Windows NT 6.1; Win64; x64)' }

for item in urls:
  print(item)
  try:
    request  = Request(item, headers=hdr)
    response = urlopen(request, context=ctx)

    try:
      html = str(response.read())
      print(html[0:100])
    except:
       print("Read Error: " + item.url)
  except HTTPError as e:
    print("HTTP Error: " + str(e.code) + " for " + str(item))
  except URLError as e:
    print("URL Error:  " + str(e.reason) + " for " + str(item))

