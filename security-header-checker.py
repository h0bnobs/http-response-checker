import argparse
from wsgiref import headers

import requests
from termcolor import colored
from urllib.parse import urlparse
import re
import json


# requirements : import requests, from termcolor import colored

def banner():
    text = r"""
       .__            
  _____|  |__   ____  
 /  ___/  |  \_/ ___\ 
 \___ \|   Y  \  \___ 
/____  >___|  /\___  >
     \/     \/     \/ 
usage: security-header-checker -u <url> -i <input_file>
"""
    print(text)


def parse_args():
    parser = argparse.ArgumentParser(description='Security header checker')
    parser.add_argument('-u', '--url', dest="target", help='Target url')
    parser.add_argument('-i', '--input_file', dest="input_file", help='Input file')
    return parser.parse_args()


COLOURS = {
    "plus": "\033[1;34m[\033[1;m\033[1;32m+\033[1;m\033[1;34m]",
    "minus": "\033[1;34m[\033[1;m\033[1;31m-\033[1;m\033[1;34m]",
    "cross": "\033[1;34m[\033[1;m\033[1;31mx\033[1;m\033[1;34m]",
    "star": "\033[1;34m[*]\033[1;m",
    "warn": "\033[1;34m[\033[1;m\033[1;33m!\033[1;m\033[1;34m]",
    "end": "\033[1;m"
}


def pretty(d, indent=0):
    for key, value in d.items():
        print('\t' * indent + colored(str(key), "red"))
        if isinstance(value, dict):
            pretty(value, indent + 1)
        else:
            print('\t' * (indent + 1) + str(value))


def ffuf_parser(json_string):
    """
    Parses the file that the tool ffuf outputs when the -o flag is used.
    :param json_string: The json that ffuf outputs as a String.
    :return urls: Returns the urls that ffuf outputs as a List.
    """
    data = json.loads(json_string)
    results = data.get('results', [])
    urls = [result.get('url') for result in results]
    return urls


def dirb_parser(filename):
    """
    Parses the file that the tool dirb outputs when the flag -o is used.
    :param filename: The exact NAME of the file. Needs to be in the same directory.
    :return target_urls: The urls that dirb found in the scan as a List.
    """
    target_urls = []
    url_pattern = re.compile(r'^\+\s+(https?://[^\s]+)')
    with open(filename, 'r') as file:
        lines = file.readlines()
    in_url_section = False
    for line in lines:
        if '---- Scanning URL:' in line:
            in_url_section = True
        elif line.strip() == '':
            in_url_section = False
        elif in_url_section:
            match = url_pattern.match(line)
            if match:
                target_urls.append(match.group(1))

    return target_urls


def output_type(filename):
    """
    Determines which tool this file came from, e.g. ffuf, dirb, gobuster etc.
    :param filename: The exact NAME of the file. Needs to be in the same directory.
    :return String: The name of the tool that was used to generate this file.
    """
    with open(filename, 'r') as file:
        lines = file.readlines()
    for line in lines:
        if '---- Scanning URL:' in line:
            #its a dirb output
            return 'dirb'
        elif 'commandline":"ffuf' in line:
            #its a ffuf output
            return 'ffuf'
        else:
            return 'txt'


def get_cookies(target_url):
    cookies = requests.get(target_url).cookies
    for cookie in cookies:
        print(cookie.name, cookie.value)

def get_headers(target_url):
    """
    Prints the security headers that match both owasp's HTTP security headers list and those that are used by the page.
    :param target_url: The page that was scanned.
    :return: Nothing
    """
    count = 0
    response = requests.get(target_url)
    headers = response.headers
    header_value = response.headers.items()
    # https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html
    security_headers = {
        "X-Frame-Options": "Recommendation is to either use Content Security Policy (CSP) frame-ancestors directive if "
                           "possible, or: X-Frame-Options: DENY",
        "X-XSS-Protection": "Recommendation is to use a Content Security Policy (CSP) that disables the use of inline js "
                            "or X-XSS-Protection: 0",
        "X-Content-Type-Options": "X-Content-Type-Options: nosniff",
        "Referrer-Policy": "Recommendation is to use Referrer-Policy: strict-origin-when-cross-origin",
        "Content-Type": "Recommendation is to set Content-Type: text/html; charset=UTF-8 to prevent XSS in HTML pages",
        "Strict-Transport-Security": "Recommendation is to use Strict-Transport-Security: max-age=63072000; "
                                     "includeSubDomains; preload",
        "Expect-CT": "Recommendation is to avoid using Expect-CT header. Mozilla recommends removing it from existing "
                     "code if possible.",
        "Content-Security-Policy": "Recommendation is to carefully configure and maintain Content Security Policy. Refer "
                                   "to Content Security Policy Cheat Sheet for customization options.",
        "Access-Control-Allow-Origin": "Recommendation is to set specific origins rather than '*' if you use this header. "
                                       "For example: Access-Control-Allow-Origin: https://yoursite.com",
        "Cross-Origin-Opener-Policy": "Recommendation is to use HTTP Cross-Origin-Opener-Policy: same-origin to isolate "
                                      "the browsing context exclusively to same-origin documents.",
        "Cross-Origin-Embedder-Policy": "Recommendation is to use Cross-Origin-Embedder-Policy: require-corp to ensure "
                                        "documents can only load resources from the same origin or explicitly marked as "
                                        "loadable.",
        "Cross-Origin-Resource-Policy": "Recommendation is to use Cross-Origin-Resource-Policy: same-site to limit "
                                        "resource loading to the site and sub-domains only.",
        "Permissions-Policy": "Recommendation is to disable all features that your site does not need or allow them only "
                              "to authorized domains. For example: Permissions-Policy: geolocation=(), camera=(), "
                              "microphone=()",
        "FLoC": "Recommendation is to declare that your site does not want to be included in the user's list of sites for "
                "cohort calculation by using Permissions-Policy: interest-cohort=().",
        "Server": "Recommendation is to remove this header or set non-informative values. For example: Server: webserver",
        "X-Powered-By": "Recommendation is to remove all X-Powered-By headers.",
        "X-AspNet-Version": "Recommendation is to disable sending this header by adding <httpRuntime "
                            "enableVersionHeader=\"false\" /> in your web.config.",
        "X-AspNetMvc-Version": "Recommendation is to disable sending this header by adding "
                               "MvcHandler.DisableMvcResponseHeader = true; in Global.asax.",
        "X-DNS-Prefetch-Control": "Recommendation is to use X-DNS-Prefetch-Control: off to disable DNS prefetch if you do "
                                  "not control links on your website.",
        "Public-Key-Pins": "Recommendation is to not use Public-Key-Pins header as it is deprecated."
    }
    pretty_print = {}
    print("\n" + COLOURS["plus"] + " Printing headers from " + target_url + " for inspection:" + COLOURS["end"] + "\n")
    for header in headers:
        # if there are security headers present, we need to see them so that we can
        if header in security_headers.keys():
            count += 1
            print(str(count) + ") The header: " + colored("" + header + ": " + headers[header], "red") + " is present on this page")
            pretty_print.update({str(count) + ") " + header: security_headers[header]})
    print("\n")
    pretty(pretty_print)


if __name__ == '__main__':
    banner()

    # TODO: make the url a txt file with a bunch of directories with a base url.
    # TODO: show the headers that aren't present.
    # TODO: cookie attributes/flags.

    args = parse_args()

    #if the -u flag is used:
    if args.target:
        parsed_url = urlparse(args.target)
        base_url = parsed_url.netloc
        print("\n" + COLOURS["plus"] + " Base URL: " + base_url + COLOURS["end"])
        get_headers(args.target)
    #or if the -i flag is used:
    elif args.input_file:
        f = open(args.input_file, "r")
        tool_name = output_type(args.input_file)
        data = f.read()
        if tool_name == 'ffuf':
            urls = ffuf_parser(data)
            for url in urls:
                get_headers(url)
        elif tool_name == 'dirb':
            urls = dirb_parser(args.input_file)
            for url in urls:
                get_headers(url)
        elif tool_name == 'txt':
            with open(args.input_file, "r") as f:
                for line in f:
                    url = line.strip()
                    get_headers(url)

    get_cookies(args.target)
