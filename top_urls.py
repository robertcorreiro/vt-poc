import re
import csv

from collections import Counter

def filter_out(url):
    whitelist = ['google.com', 'chrome-extension', 'sas.com', 'service-now',
                 'sasinstitute', 'chase.com']
    for w in whitelist:
        if re.search(w, url):
            return True

urls = Counter()
with open('history.tsv') as f:
    tsvfile = csv.reader(f, delimiter='\t')
    for i, entry in enumerate(tsvfile):
        url = entry[0]
        if filter_out(url):
            continue
        urls[url] += 1


with open('top100.txt', 'w') as f:
    for url in Counter(urls).most_common(100):
        f.write(url[0] + '\n')


