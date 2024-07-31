from zapv2 import ZAPv2

# Initialize ZAP instance
zap = ZAPv2(apikey='your_zap_api_key')

# Target URL 
target = 'http://example.com'

# Start ZAP scan
zap.urlopen(target)
print('Spidering target {}'.format(target))
zap.spider.scan(target)

# Wait for the spidering to complete
while int(zap.spider.status()) < 100:
    print('Spider progress %: {}'.format(zap.spider.status()))
    time.sleep(2)

print('Spider completed')
print('Scanning target {}'.format(target))
zap.ascan.scan(target)

# Wait for the scanning to complete
while int(zap.ascan.status()) < 100:
    print('Scan progress %: {}'.format(zap.ascan.status()))
    time.sleep(2)

print('Scan completed')
# Get the results
alerts = zap.core.alerts(baseurl=target)
print(alerts)
