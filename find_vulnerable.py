import requests

def load_dorks(filename):
    with open(filename, 'r') as f:
        return [line.strip() for line in f if line.strip()]

def search_dork(dork):
    # Placeholder: Replace with a real search or API call
    # For demonstration, returns a dummy list
    print(f"Searching for dork: {dork}")
    return [
        f"http://example.com/page.php?id=1&dork={dork}"
    ]

def is_vulnerable(url):
    # Placeholder: Replace with actual SQLi detection logic
    print(f"Testing URL: {url}")
    try:
        test_url = url + "'"
        resp = requests.get(test_url, timeout=5)
        errors = ["You have an error in your SQL syntax",
                  "Warning: mysql_fetch",
                  "Unclosed quotation mark after the character string",
                  "quoted string not properly terminated"]
        for error in errors:
            if error.lower() in resp.text.lower():
                return True
    except Exception as e:
        print(f"Error testing {url}: {e}")
    return False

def main():
    dorks = load_dorks('dorks.txt')
    vulnerable_urls = []
    for dork in dorks:
        urls = search_dork(dork)
        for url in urls:
            if is_vulnerable(url):
                print(f"[+] Vulnerable: {url}")
                vulnerable_urls.append(url)
    with open('vulnerable.txt', 'w') as out:
        for url in vulnerable_urls:
            out.write(url + '\n')

if __name__ == "__main__":
    main()