import argparse
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager
import requests
from termcolor import colored
import re
import json
import ast
import sys

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


def banner():
    banner = """
     _          
    | |         
 ___| |__   ___ 
/ __| '_ \ / __|
\__ \ | | | (__ 
|___/_| |_|\___|

https://github.com/h0bnobs/http-response-checker

usage: security-header-checker.py -i <input_file> -u <target_url> -q -o <output_file>
    """
    print(colored(banner, 'yellow'))


def parse_args():
    """
    Parses command line arguments.
    :return: The arguments parsed from the command line.
    """
    parser = argparse.ArgumentParser(description='Security header checker')
    parser.add_argument('-u', '--url', dest="target", help='The single target URL to be scanned')
    parser.add_argument('-i', '--input_file', dest="input_file", help='Input file')
    parser.add_argument('-o', '--output_file', dest="output_file", help='Sends output to a file')
    parser.add_argument('-q', '--quiet', dest="quiet", action='store_true', help='Prints far less to terminal')
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


def print_cookies(cookies, target_url):
    """
    Prints the cookies of the target page. Uses selenium to find the cookies, meaning it'll flash a chrome window up.
    :param target_url: The url of the page.
    """

    # nice printing
    if len(cookies) > 0:
        if len(cookies) == 1:
            print("\n " + COLOURS["plus"] + " The following cookie was found on " + target_url + ":" + COLOURS["end"])
            print(json.dumps(cookies, indent=4))
        else:
            print("\n " + COLOURS["plus"] + " The following " + str(
                len(cookies)) + " cookies were found on " + target_url + ":" + COLOURS["end"])
            print(json.dumps(cookies, indent=4))
    else:
        print("\n " + COLOURS["cross"] + " No cookies found on " + target_url + COLOURS["end"])


def print_headers(headers, target_url):
    """
    Prints the security headers that match both owasp's HTTP security headers list and those that are used by the page.
    :param target_url: The page that was scanned.
    """
    count = 0
    # pretty printing logic
    pretty_print = {}
    print("\n" + COLOURS["plus"] + " Here are the headers from " + target_url + " for inspection:" + COLOURS[
        "end"] + "\n")
    for header in headers:
        # if there are security headers present, we need to see them so that we can
        if header in security_headers.keys():
            count += 1
            print(str(count) + ") " + colored("" + header + ": " + headers[header], "red"))
            pretty_print.update({str(count) + ") " + header: security_headers[header]})
    print("\n" + COLOURS["plus"] + " Here are the recommendations for the security headers that were found on " + ":" +
          COLOURS["end"] + "\n")
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
            h.update({header: headers[header]})
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
    # options for headless mode so it doesnt flash on screen - gpt special
    chrome_options = Options()
    chrome_options.add_argument("--headless")  # Run in headless mode
    chrome_options.add_argument("--no-sandbox")  # Required for some environments
    chrome_options.add_argument("--disable-dev-shm-usage")  # Overcome limited resource problems

    driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=chrome_options)

    try:
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
    finally:
        driver.quit()

    return final_cookies


if __name__ == '__main__':
    banner()
    args = parse_args()

    if args.quiet and not args.output_file:
        print(COLOURS["warn"] + " Cannot use -q without -o!")
        sys.exit()


    def create_or_empty_file(filename):
        """
        Creates a file if it doesn't exist, or it wipes it if it does exist.
        :param filename: The name of the file to be created/wiped.
        :return:
        """
        if filename:
            with open(filename, 'w') as file:
                file.write('')


    if args.output_file:
        create_or_empty_file(args.output_file)


    def process_url(url):
        """
        Gets the headers and cookies for the inputted url. If -q and -o are present then it prints nothing. Otherwise,
        it prints, then if -o is present it outputs to a file.
        :param url: The target url to be checked.
        """
        unformatted_headers = get_headers(url)
        unformatted_cookies = get_cookies(url)

        formatted_headers = json.dumps(unformatted_headers, indent=4)
        formatted_cookies = json.dumps(unformatted_cookies, indent=4)
        output_content = (
            f"\nHeaders for {url}:\n{formatted_headers}\n"
            f"\nCookies for {url}:\n{formatted_cookies}\n"
        )

        if args.quiet and args.output_file:
            with open(args.output_file, 'a') as file:
                file.write(output_content)
                return
        else:
            print_headers(unformatted_headers, url)
            print_cookies(unformatted_cookies, url)
            if args.output_file:
                with open(args.output_file, 'a') as file:
                    file.write(output_content)


    # if -u is used
    if args.target:
        process_url(args.target)

    # if -i is used
    if args.input_file:
        try:
            tool_name = output_type(args.input_file)
            with open(args.input_file, 'r') as file:
                data = file.read()
        except FileNotFoundError:
            print("\n" + COLOURS[
                "warn"] + " FileNotFoundError: [Errno 2] No such file or directory: '" + args.input_file + "'")
            sys.exit()

        urls = []
        if tool_name == 'ffuf':
            urls = ffuf_parser(data)
        elif tool_name == 'dirb':
            urls = dirb_parser(args.input_file)
        elif args.input_file.endswith('.txt'):
            urls = [line.strip() for line in data.splitlines()]
        elif tool_name is None and not args.input_file.endswith('.txt'):
            print("\n" + COLOURS["warn"] + " Input file not recognised/supported/correct!" + COLOURS["end"])
            message = (
                f"\n{colored('Currently only supporting ', 'red')}"
                f"{colored('dirb', 'green')}"
                f"{colored(' and ', 'red')}"
                f"{colored('ffuf', 'green')}"
                f"{colored(' outputs and ', 'red')}"
                f"{colored('.txt', 'green')}"
                f"{colored(' files in the following format:', 'red')}\n\n"
                "https://example.com/\n"
                "https://example.com/page"
                f"\n\n{colored('I would recommend not including pages that responded with 403 or 500', 'red')}"
            )
            print(message)
            sys.exit()

        count = 0
        total_urls = len(urls)

        quarter_mark = total_urls / 4
        half_mark = total_urls / 2
        three_quarters_mark = 3 * total_urls / 4

        printed_quarter = False
        printed_half = False
        printed_three_quarters = False

        for url in urls:
            count += 1
            process_url(url)

            if total_urls >= 8:
                if count > quarter_mark and not printed_quarter:
                    print(colored('\n\n### Quarter of the way through ###\n', 'yellow'))
                    printed_quarter = True
                if count > half_mark and not printed_half:
                    print(colored('\n\n### Halfway through ###\n', 'yellow'))
                    printed_half = True
                if count > three_quarters_mark and not printed_three_quarters:
                    print(colored('\n\n### Three quarters of the way through ###\n', 'yellow'))
                    printed_three_quarters = True
