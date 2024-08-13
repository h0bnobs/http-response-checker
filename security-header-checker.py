import argparse
from wsgiref import headers
from selenium import webdriver
import json
import requests
from termcolor import colored
from urllib.parse import urlparse
import re
import json
import os
import ast

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
    "Public-Key-Pins": "Recommendation is to not use Public-Key-Pins header as it is deprecated.",
    "Set-Cookie": "test"
}


# requirements : import requests, from termcolor import colored, from selenium import webdriver

def banner():
    text = r"""
       .__            
  _____|  |__   ____  
 /  ___/  |  \_/ ___\ 
 \___ \|   Y  \  \___ 
/____  >___|  /\___  >
     \/     \/     \/ 
@h0bnobs 
usage: security-header-checker -u <url> -i <input_file> -o <output_file> -nO <output_file>
"""
    print(text)


def parse_args():
    parser = argparse.ArgumentParser(description='Security header checker')
    parser.add_argument('-u', '--url', dest="target", help='Target url')
    parser.add_argument('-i', '--input_file', dest="input_file", help='Input file')
    parser.add_argument('-o', '--output_file', dest="output_file", help='Sends output to a file')
    parser.add_argument('-nO', '--no-print-output', dest="no_print_output", help='Prints far less to terminal and '
                                                                                 'sends to output file')
    return parser.parse_args()


COLOURS = {
    "plus": "\033[1;34m[\033[1;m\033[1;32m+\033[1;m\033[1;34m]",
    "minus": "\033[1;34m[\033[1;m\033[1;31m-\033[1;m\033[1;34m]",
    "cross": "\033[1;34m[\033[1;m\033[1;31mx\033[1;m\033[1;34m]",
    "star": "\033[1;34m[*]\033[1;m",
    "warn": "\033[1;34m[\033[1;m\033[1;33m!\033[1;m\033[1;34m]",
    "end": "\033[1;m"
}


def print_pretty(dictionary, indent=0):
    """
    Prints a dictionary in a nicer form that is easier to read.
    :param dictionary: Dictionary to pretty print
    :param indent: The amount of indentation
    """
    for key, value in dictionary.items():
        print('\t' * indent + colored(str(key), "red"))
        if isinstance(value, dict):
            print_pretty(value, indent + 1)
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
            # its a dirb output
            return 'dirb'
        elif 'commandline":"ffuf' in line:
            # its a ffuf output
            return 'ffuf'


def print_cookies(target_url):
    """
    Prints the cookies of the target page. Uses selenium to find the cookies, meaning it'll flash a chrome window up.
    :param target_url: The url of the page.
    """
    driver = webdriver.Chrome()
    driver.get(target_url)
    cookies = driver.get_cookies()
    final_cookies = []
    for dictionary in cookies:
        temp_dictionary = {
            "name": dictionary["name"],
            "value": dictionary["value"],
            "httpOnly": dictionary['httpOnly'],
            "secure": dictionary['secure']
        }
        final_cookies.append(temp_dictionary)

    # nice printing
    if len(final_cookies) > 0:
        if len(final_cookies) == 1:
            print("\n " + COLOURS["plus"] + " The following cookie was found on " + target_url + ":" + COLOURS["end"])
        print("\n " + COLOURS["plus"] + " The following cookies were found on " + target_url + ":" + COLOURS["end"])
        print(json.dumps(final_cookies, indent=4))
    else:
        print("\n " + COLOURS["cross"] + " No cookies found on " + target_url + COLOURS["end"])


def print_headers(target_url):
    """
    Prints the security headers that match both owasp's HTTP security headers list and those that are used by the page.
    :param target_url: The page that was scanned.
    """
    count = 0
    response = requests.get(target_url)
    headers = response.headers

    # pretty printing logic
    pretty_print = {}
    print("\n" + COLOURS["plus"] + " Printing headers from " + target_url + " for inspection:" + COLOURS["end"] + "\n")
    for header in headers:
        # if there are security headers present, we need to see them so that we can
        if header in security_headers.keys():
            count += 1
            print(str(count) + ") The header: " + colored("" + header + ": " + headers[header],
                                                          "red") + " is present on this page")
            pretty_print.update({str(count) + ") " + header: security_headers[header]})
    print("\n")
    print_pretty(pretty_print)


def get_headers(target_url):
    """
    Returns the security headers that match both owasp's HTTP security headers list and those that are used by the page.
    :param target_url: The page that was scanned.
    :return headers: A dictionary of the headers that match owasp's list.
    """
    response = requests.get(target_url)
    headers = response.headers
    h = {}
    for header in headers:
        if header in security_headers.keys():
            h.update({header: security_headers[header]})
    return h


def format_dictionary_file(filepath):
    """
    Rewrites a file that contains the string representation of a dictionary.
    :param filepath: The file that constains the dictionary
    """
    with open(filepath, 'r') as file:
        content = file.read()
    try:
        dictionary = ast.literal_eval(content)
        if not isinstance(dictionary, dict):
            raise ValueError("The file content is not a valid dictionary.")
    except (SyntaxError, ValueError) as e:
        print(f"Error reading dictionary from file: {e}")
        return
    formatted_content = json.dumps(dictionary, indent=4)
    with open(filepath, 'w') as file:
        file.write(formatted_content)


def get_cookies(target_url):
    """
    Gets the cookies of the target page. Uses selenium to find the cookies, meaning it'll flash a chrome window up.
    :param target_url: The url of the page.
    :return final_cookies: A dictionary of the cookies.
    """
    driver = webdriver.Chrome()
    driver.get(target_url)
    cookies = driver.get_cookies()
    final_cookies = []
    for dictionary in cookies:
        temp_dictionary = {
            "name": dictionary["name"],
            "value": dictionary["value"],
            "httpOnly": dictionary['httpOnly'],
            "secure": dictionary['secure']
        }
        final_cookies.append(temp_dictionary)

    return final_cookies


if __name__ == '__main__':
    banner()

    # TODO: make the url a txt file with a bunch of directories with a base url.
    # TODO: just -o

    args = parse_args()

    # if -u and -nO
    if args.target and args.no_print_output:
        filename = args.no_print_output
        if os.path.exists(filename):
            with open(filename, 'w') as file:
                file.write(f"Headers:\n")
        if not os.path.exists(filename):
            with open(filename, 'w') as file:
                file.write('Headers:')
        formatted_content = json.dumps(get_headers(args.target), indent=4)
        with open('output', 'a') as file:
            file.write(formatted_content)
        formatted_content = json.dumps(get_cookies(args.target), indent=4)
        with open('output', 'a') as file:
            file.write(f"\nCookies:\n")
            file.write(formatted_content)

    # or if -i and -nO
    elif args.input_file and args.no_print_output:
        print("####")

    if not args.no_print_output:
        # if just the -u flag is used:
        if args.target:
            parsed_url = urlparse(args.target)
            base_url = parsed_url.netloc
            print("\n" + COLOURS["plus"] + " Base URL: " + base_url + COLOURS["end"])
            print_headers(args.target)
            print_cookies(args.target)
        # or if the -i flag is used:
        elif args.input_file: # TODO: determine if its a simple .txt file
            f = open(args.input_file, "r")
            tool_name = output_type(args.input_file)
            data = f.read()
            if tool_name == 'ffuf':
                urls = ffuf_parser(data)
                for url in urls:
                    print_headers(url)
                    print_cookies(url)
            elif tool_name == 'dirb':
                urls = dirb_parser(args.input_file)
                for url in urls:
                    print_headers(url)
                    print_cookies(url)
