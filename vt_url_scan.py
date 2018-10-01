import requests
import json
import time

from datetime import datetime

def bundle_urls(filename):
    """VirusTotal's free API limited to 4 req/min """

    with open(filename, "r") as f:
        urls = f.readlines()
    urls = [l.strip() for l in urls ] 

    batch = []
    batches = []

    for i, url in enumerate(urls):
        if i > 0 and i % 4 == 0:
            batches.append(batch)
            batch = []
        batch.append(url)
    if batch: # if len(urls) isn't a multipe of 4, add the last batch
        batches.append(batch)
    return batches

def query_urls(batch):
    resource = "\n".join(batch)

    headers = {
        "Accept-Encoding": "gzip, deflate",
        "User-Agent" : "Python Requests Library Example"
    }
    params = {
        "apikey": "", 
        "resource": resource
    }

    response = requests.post("https://www.virustotal.com/vtapi/v2/url/report",
              params=params, headers=headers)
    return response.json()

def find_positives(results):
    positives = []
    # expecting 4 results per batch
    for result in results:
        if result["response_code"] == 1 and result["positives"] >= 2: # tracking 2+ hits
            positives.append(result)
    return positives

def main():
    filename = "top100.txt"

    batches = bundle_urls(filename)
    positive_results = []
    for batch in batches:
        json_response = query_urls(batch)
        hits = find_positives(json_response)
        if hits:
            positive_results.append(hits)
        time.sleep(60)

    if positive_results:
        out_fn = "url_scan_" + str(datetime.now().strftime("%Y_%m_%d_%H_%M_%S")) + ".json"
        with open(out_fn, "w") as f:
           json.dump(positive_results, f, ensure_ascii=False)


if __name__ == "__main__":
    main()
