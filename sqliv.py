# SQLiv v2.0
# Ghost (github.com/Hadesy2k)
# official.ghost@tuta.io

import argparse
from urlparse import urlparse

from src import std
from src import scanner
from src import reverseip
from src import serverinfo
from src.web import search
from src.crawler import Crawler

# search engine instance
bing   = search.Bing()
google = search.Google()
yahoo = search.Yahoo()

# crawler instance
crawler = Crawler()

def singlescan(url):
    """instance to scan single targeted domain"""

    if urlparse(url).query != '':
        result = scanner.scan([url])
        if result != []:
            # scanner.scan print if vulnerable
            # therefore exit
            return result

        else:
            print ""  # move carriage return to newline
            std.stdout("no SQL injection vulnerability found")
            option = std.stdin("do you want to crawl and continue scanning? [Y/N]", ["Y", "N"], upper=True)

            if option == 'N':
                return False

    # crawl and scan the links
    # if crawl cannot find links, do some reverse domain
    std.stdout("going to crawl {}".format(url))
    urls = crawler.crawl(url)

    if not urls:
        std.stdout("found no suitable urls to test SQLi")
        #std.stdout("you might want to do reverse domain")
        return False

    std.stdout("found {} urls from crawling".format(len(urls)))
    vulnerables = scanner.scan(urls)

    if vulnerables == []:
        std.stdout("no SQL injection vulnerability found")
        return False

    return vulnerables

def initparser():
    """initialize parser arguments"""

    global parser
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", dest="dork", help="SQL injection dork", type=str, metavar="inurl:example")
    parser.add_argument("-e", dest="engine", help="search engine [Bing, Google, and Yahoo]", type=str, metavar="bing, google, yahoo")
    parser.add_argument("-p", dest="page", help="number of websites to look for in search engine", type=int, default=10, metavar="100")
    parser.add_argument("-t", dest="target", help="scan target website", type=str, metavar="www.example.com")
    parser.add_argument('-r', dest="reverse", help="reverse domain", action='store_true')
    parser.add_argument('-o', dest="output", help="output result into json", type=str, metavar="result.json")
    parser.add_argument('--dorks-file', dest="dorks_file", help="File with dorks, one per line", type=str)

if __name__ == "__main__":
    initparser()
    args = parser.parse_args()

    vulnerableurls = []

    # Multiple dork support
    if args.dorks_file:
        std.stdout("reading dorks from file: {}".format(args.dorks_file))
        with open(args.dorks_file, "r") as f:
            dorks = [line.strip() for line in f if line.strip()]
        for dork in dorks:
            std.stdout("searching for websites with dork: {}".format(dork))
            if args.engine in ["bing", "google", "yahoo"]:
                websites = eval(args.engine).search(dork, args.page)
            else:
                std.stdout("unsupported search engine: {}".format(args.engine))
                continue
            vulnerables = scanner.scan(websites)
            if vulnerables:
                vulnerableurls.extend([result[0] for result in vulnerables])
        # Output to vulnerable.txt
        with open("vulnerable.txt", "w") as fout:
            for url in vulnerableurls:
                fout.write(url + "\n")
        if vulnerableurls:
            std.stdout("Vulnerable targets written to vulnerable.txt")
        else:
            std.stdout("No vulnerable targets found.")
        exit(0)

    # Single dork mode
    if args.dork != None and args.engine != None:
        std.stdout("searching for websites with given dork")

        # get websites based on search engine
        if args.engine in ["bing", "google", "yahoo"]:
            websites = eval(args.engine).search(args.dork, args.page)
        else:
            std.stdout("unsupported search engine: {}".format(args.engine))
            exit(1)

        vulnerables = scanner.scan(websites)
        vulnerableurls = [result[0] for result in vulnerables]
        # add server info
        if vulnerables:
            table_data = serverinfo.check(vulnerableurls)
            for result, info in zip(vulnerables, table_data):
                info.insert(1, result[1])  # database name
            std.fullprint(table_data)
        # Output to vulnerable.txt
        with open("vulnerable.txt", "w") as fout:
            for url in vulnerableurls:
                fout.write(url + "\n")
        if vulnerableurls:
            std.stdout("Vulnerable targets written to vulnerable.txt")
        else:
            std.stdout("No vulnerable targets found.")
        exit(0)

    # scan SQLi of given site
    elif args.target:
        vulnerables = singlescan(args.target)

        if not vulnerables:
            exit(0)

        # show domain information of target urls
        std.stdout("getting server info of domains can take a few mins")
        table_data = serverinfo.check([args.target])

        std.printserverinfo(table_data)
        print ""  # give space between two table
        std.normalprint(vulnerables)
        # Output to vulnerable.txt
        with open("vulnerable.txt", "w") as fout:
            for result in vulnerables:
                if isinstance(result, (list, tuple)):
                    fout.write(result[0] + "\n")
                else:
                    fout.write(str(result) + "\n")
        std.stdout("Vulnerable targets written to vulnerable.txt")
        exit(0)

    # print help message, if no parameter is provided
    else:
        parser.print_help()

    # dump result into json if specified
    if args.output != None:
        std.dumpjson(vulnerables, args.output)
