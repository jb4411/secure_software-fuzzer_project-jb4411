"""
file: fuzz.py
description: This program is a fuzzer for testing and exploiting DVWA.
language: python3
author: jb4411@g.rit.edu Jesse Burdick-Pless
"""
import time
import mechanicalsoup
import sys
import os
from enum import Enum


# An enumeration of the possible commands given on the command line
class Command(Enum):
    DISCOVER = 0,
    TEST = 1


class TestResults:
    """
    Class: TestResults
    Description: TestResults holds the results of tests on specific pages, as well as the number times
    different elements have been seen.
    """
    def __init__(self, pages=None, counts=None):
        if pages is None:
            pages = {}
        if counts is None:
            counts = {}
        self.pages = pages
        self.counts = counts

    def __add__(self, other):
        if type(other) != TestResults:
            return None
        pages = self.pages.copy()
        pages.update(other.pages)
        counts = self.counts.copy()
        for item in other.counts:
            if item not in counts:
                counts[item] = 0
            counts[item] += other.counts[item]
        return TestResults(pages, counts)

    def get_pages(self):
        """
        Return this object's dictionary of pages.
        :return: this object's dictionary of pages
        """
        return self.pages

    def add_page(self, page, results: list):
        """
        Add a page to this object's dictionary of pages.
        :param page: the page to be added
        :param results: the results to associate with said page
        :return: None
        """
        if page not in self.pages:
            self.pages[page] = {}
        if results[0] not in self.pages[page]:
            self.pages[page][results[0]] = set()
        self.pages[page][results[0]].update(results[1])

    def increment(self, element):
        """
        Increment the count associated with the element passed in.
        :param element: the element to increment the count of
        :return: None
        """
        if element not in self.counts:
            self.counts[element] = 0
        self.counts[element] += 1

    def get_counts(self):
        """
        Return this object's dictionary of counts.
        :return: this object's dictionary of counts
        """
        return self.counts


# Universal options
CUSTOM_AUTH = "--custom-auth"
COMMON_WORDS = "--common-words"
EXTENSIONS = "--extensions"

# Test mode only options
VECTORS = "--vectors"
SANITIZED_CHARS = "--sanitized-chars"
SENSITIVE = "--sensitive"
SLOW = "--slow"

# The set of valid options when in discover mode
DISCOVER_OPTIONS = {CUSTOM_AUTH, COMMON_WORDS, EXTENSIONS}

# The set of valid options when in test mode
TEST_OPTIONS = {CUSTOM_AUTH, COMMON_WORDS, EXTENSIONS, VECTORS, SANITIZED_CHARS, SENSITIVE, SLOW}


def error(error_msg):
    """
    Used to print a general error message as well as the usage statement.
    Print the usage message, as well as the error message passed in.
    :param error_msg: the error message to be printed
    :return: None
    """
    print("usage: fuzz [discover | test] url OPTIONS")
    print("fuzz.py: error:", error_msg)
    print()


def parse_error(error_msg):
    """
    Used to print a parsing error message.
    Print the error message passed in.
    :param error_msg: the error message to be printed
    :return: None
    """
    print("fuzz.py: error while parsing options:", error_msg)
    print()


def missing_option_error(option):
    """
    Used to print an error message when a required option is missing.
    :param option: the missing option
    :return: None
    """
    error("option missing: '" + str(option) + "' is required")


def print_commands():
    """
    Print all valid commands, as well as what those commands do.
    :return: None
    """
    print("COMMANDS:")
    print("\tdiscover  Output a comprehensive, human-readable list of all discovered inputs to the system. Techniques "
          "include both crawling and guessing.")
    print("\ttest      Discover all inputs, then attempt a list of exploit vectors on those inputs. Report anomalies "
          "that could be vulnerabilities.")


def print_options():
    """
    Print all valid options, as well as what those options require.
    :return: None
    """
    # general options
    print("OPTIONS:\n")
    print("\tOptions can be given in any order.\n")
    print("\t--custom-auth=string     Signal that the fuzzer should use hard-coded authentication for a specific "
          "application (e.g. dvwa).\n")

    # discover options
    print("\tDiscover options:")
    print("\t  --common-words=file    Newline-delimited file of common words to be used in page guessing. Required.")
    print("\t  --extensions=file      Newline-delimited file of path extensions, e.g. \".php\". Optional. Defaults to "
          "\".php\" and the empty string if not specified\n")

    # test options
    print("\tTest options:")
    print("\t  --common-words=file    Same option as in discover - see above.")
    print("\t  --extensions=file      Same option as in discover - see above.")
    print("\t  --vectors=file         Newline-delimited file of common exploits to vulnerabilities. Required.")
    print("\t  --sanitized-chars=file Newline-delimited file of characters that should be sanitized from inputs. "
          "Defaults to just < and >")
    print("\t  --sensitive=file       Newline-delimited file data that should never be leaked. It's assumed that this "
          "data is in the application's database (e.g. test data), but is not reported in any response. Required.")
    print("\t  --slow=500             Number of milliseconds considered when a response is considered \"slow\". "
          "Optional. Default is 500 milliseconds")


def parse_options(valid_options, command):
    """
    Parse and validate the options given on the command line.
    If an option that requires a file is parsed, check that the file exists.
    If '--slow' is parsed, check that the number given can be converted to an integer
    :param valid_options: the set of valid options for the given command
    :param command: the given command
    :return: a dictionary of the parsed and validated options
    """
    special_options = {CUSTOM_AUTH, SLOW}
    parsed_options = dict()
    for option_input in sys.argv[3:]:
        option_parts = option_input.split("=", maxsplit=1)
        option = option_parts[0]
        option_value = option_parts[1]
        # verify that the given option is valid for the current mode
        if option not in valid_options:
            parse_error("invalid option provided: \"" + option + "\"")
            print_options()
            return None
        # verify that the given option has not already been provided
        if option in parsed_options.keys():
            parse_error("duplicate option provided: \"" + option + "=" + option_value + "\" and \"" + option + "=" +
                        option_value + "\"")
            return None
        if option in special_options:
            # handle options that do not require a file
            if option == SLOW:
                try:
                    parsed_options[option] = int(option_value)
                except ValueError:
                    parse_error("could not parse \"--slow=" + option_value +
                                "\", the value given could not be converted to an integer")
                    return None
            else:
                parsed_options[option] = str(option_value)
        else:
            # handle options that require a file
            file_exists_windows = os.path.exists(option_value)
            file_exists_unix = os.path.exists("/" + option_value)
            file_exists = file_exists_windows or file_exists_unix
            if not file_exists:
                parse_error("could not find provided file: \"" + option_value + "\"")
                return None
            parsed_options[option] = option_value

    # set the list of required options for the given command
    if command == Command.TEST:
        required = [COMMON_WORDS, VECTORS, SENSITIVE]
    else:
        required = [COMMON_WORDS]

    # verify all required options have been provided
    for op in required:
        if op not in parsed_options:
            missing_option_error(op)
            return None

    return parsed_options


def custom_auth(url):
    """
    Called when the '--custom-auth' option is present.
    Automatically go to the DVWA setup and login pages as they are already known.
    :param url: the URL given on the command line
    :return: the MechanicalSoup browser used to interact with DVWA
    """
    browser = mechanicalsoup.StatefulBrowser(user_agent='MechanicalSoup')
    browser.open(url + "/setup.php")
    browser.select_form('form[action="#"]')
    browser.submit_selected()
    browser.open(url)
    browser.select_form('form[action="login.php"]')
    browser["username"] = "admin"
    browser["password"] = "password"
    browser.submit_selected()
    browser.open(url + "/security.php")
    browser.select_form('form[action="#"]')
    browser.form.set_select({"security": "low"})
    browser.submit_selected()
    browser.open(url)
    return browser


def print_title(title_str):
    """
    A helper method used to print a title as part of the human-readable output.
    :param title_str: the title to be printed
    :return: None
    """
    print("\n" + title_str)
    print("-" * len(title_str))


def delim(input_str, max_len, delim_str=" "):
    """
    A helper method for finding the correct spacing delimiters for the given input string such that it will line up
    with the rows above and below this row.
    :param input_str: the given input string
    :param max_len: the length of the longest input string
    :param delim_str: the character to be used for spacing, " " by default
    :return: the delimiter to go before the given input string, the delimiter to go after the given input string
    """
    delim_len = max_len - len(input_str) + 6
    # set pre string delimiter
    pre_delim = delim_str * (delim_len // 2)
    # set post string delimiter
    if (delim_len % 2) == 0:
        post_delim = delim_str * (delim_len // 2)
    else:
        post_delim = delim_str * ((delim_len // 2) + 1)

    return pre_delim, post_delim


def print_aligned_with_delim(name, max_name_length, value, max_value_length):
    """
    A helper method for printing a row with two values such that the delimiters will be lined up with those in the rows
    above and below this row.
    :param name: the name of the field
    :param max_name_length: the length of the longest field name
    :param value: the value of the field
    :param max_value_length: the length of the longest field value
    :return: None
    """
    line_str = "|{}{}{}|{}{}{}|"
    pre_name, post_name = delim(name, max_name_length)
    pre_value, post_value = delim(value, max_value_length)
    print(line_str.format(pre_name, name, post_name, pre_value, value, post_value))


def print_formatted_inputs(input_list):
    """
    A helper method for generating and printing human-readable output for a given list of inputs.
    :param input_list: the list of inputs to be printed
    :return: None
    """
    lst = []
    for element in input_list:
        for inpt in element[1]:
            lst.append(inpt)
    input_list = lst
    max_name_length = 0
    max_value_length = 0
    inputs = []
    for element in input_list:
        # get name (if exists)
        if "name" in element.attrs.keys():
            name = element.attrs["name"]
            max_name_length = max(max_name_length, len(name))
        else:
            name = ""
        # get value (if exists)
        if "value" in element.attrs.keys():
            value = element.attrs["value"]
            max_value_length = max(max_value_length, len(value))
        else:
            value = ""
        inputs.append((name, value))

    line_sep = " " + ("-" * (max_name_length + max_value_length + 13))
    # print heading
    print(line_sep)
    print_aligned_with_delim("Name", max_name_length, "Value", max_value_length)
    print(" " + ("=" * len(line_sep))[:-1])
    # print each input name and value
    for element in inputs:
        print_aligned_with_delim(element[0], max_name_length, element[1], max_value_length)
    print(line_sep)


def print_discovered_inputs(valid_pages, cookies):
    """
    A helper method for printing human-readable output for form inputs and cookies
    :param valid_pages: the dictionary of valid pages
    :param cookies: the set of cookies
    :return: None
    """
    # print the discovered inputs for each page
    for page in valid_pages.keys():
        if len(valid_pages[page]) > 1:
            page_title = valid_pages[page][0].contents[0]
            print_title("Page: " + page_title)
            print(page)
            print("-" * len(page))
            print(" Form inputs:")
            print_formatted_inputs(valid_pages[page][1])

    print("\n" + ("#" * 130))
    # print all cookies found
    print("\n\nCookies:")
    if len(cookies) == 0:
        sep = "-" * 8
        print(sep)
        print(sep)
        return
    line_strs = []
    max_len = 0
    for cookie in cookies:
        cookie_str = "|  {}  =  {}  ".format(cookie.name, cookie.value)
        line_strs.append(cookie_str)
        max_len = max(max_len, len(cookie_str))

    line_sep = " " + ("-" * (max_len - 1))
    print(line_sep)
    for line in line_strs:
        print(line + (" " * (max_len - len(line))) + "|")
    print(line_sep)


def find_form_parameters(browser, page, valid_pages, cookies):
    """
    This function finds all forms and their respective inputs that are on the given page.
    :param browser: the MechanicalSoup stateful browser for interacting with the website
    :param page: the page to search for form inputs
    :param valid_pages: the dictionary of valid pages
    :param cookies: the set of cookies
    :return: None
    """
    browser.open(page)
    forms = browser.page.find_all("form")
    if len(forms) > 0:
        forms_and_inputs = []
        for form in forms:
            inputs = form.find_all("input")
            forms_and_inputs.append((form, inputs))

        valid_pages[page].append(forms_and_inputs)

    # find cookies
    for cookie in browser.get_cookiejar():
        cookies.add(cookie)


def parse_urls(valid_pages):
    """
    Parse the url of each discover page to find input parameters.
    :param valid_pages: the dictionary of valid pages
    :return: the dictionary of parsed urls
    """
    parsed_urls = {}
    for url in valid_pages:
        # urls without any parameters can be added to parsed_urls as is
        if "?" not in url:
            if url not in parsed_urls.keys():
                parsed_urls[url] = [url]
            continue
        # parse out inputs
        url_parts = url.split("?")
        url = url_parts[0]
        if url not in parsed_urls.keys():
            parsed_urls[url] = [url]
        inputs = url_parts[1:]
        # add al inputs to parsed_urls[url]
        for param in inputs:
            parsed_urls[url].append(param)

    # output each parsed url
    for url in parsed_urls.keys():
        print(parsed_urls[url])

    return parsed_urls


def input_discovery(browser, valid_pages):
    """
    This function handles discovering inputs on all discovered pages.
    :param browser: the MechanicalSoup stateful browser for interacting with the website
    :param valid_pages: the dictionary of valid pages
    :return: the browser, the dictionary of parsed urls, the dictionary of valid pages, and the set of cookies
    """
    # parse urls for inputs
    print_title("Parsed URLs (from guessed pages and discovered links):")
    parsed_urls = parse_urls(valid_pages)
    print("-" * 54)
    print("\n" + ("#" * 130))
    # create a set of cookies
    cookies = set()
    # find all form inputs and cookies
    for url in parsed_urls.keys():
        find_form_parameters(browser, url, valid_pages, cookies)
    print_discovered_inputs(valid_pages, cookies)
    return browser, parsed_urls, valid_pages, cookies


def guess_pages(browser, base_url, discovered_urls, external_links, options, valid_pages):
    """
    Guess pages using the list of custom words given on the command line.
    Also use a list of extensions if one was given.
    If a guessed page exists, crawl it.
    :param browser: the MechanicalSoup stateful browser for interacting with the website
    :param base_url: the base url of the website being fuzzed
    :param discovered_urls: the set of already discovered urls
    :param external_links: the set of previously found external links
    :param options: the dictionary of parsed command line options
    :param valid_pages: the dictionary of valid pages
    :return: None
    """
    possible_pages = []
    if EXTENSIONS in options:
        with open(options.get(COMMON_WORDS)) as words, open(options.get(EXTENSIONS)) as extensions:
            for word in words:
                for extension in extensions:
                    possible_pages.append(word.strip() + extension.strip())
    else:
        with open(options.get(COMMON_WORDS)) as words:
            for word in words:
                possible_pages.append(word.strip())

    for page in possible_pages:
        sep = ""
        if base_url[-1] != "/" and page[0] != "/":
            sep = "/"
        page_url = base_url + sep + page
        response = browser.open(page_url)
        if response.status_code != 404:
            crawl_link(browser, page_url, base_url, discovered_urls, external_links, valid_pages)


def is_external(url, base_url, external_links):
    """
    Check if the given url is an external link.
    :param url: the url to check
    :param base_url: the base url of the website being fuzzed
    :param external_links: the set of previously found external links
    :return: whether the given url is an external link
    """
    if url in external_links:
        return True
    # check whether the link is relative or absolute
    has_double_slash = url.find("//")
    has_colon = url.find(":")
    absolute_link = (has_double_slash > -1) or (has_colon > -1)
    if not absolute_link:
        return False

    # extract domain from url
    if has_double_slash > -1:
        page = url[has_double_slash + 2:]
    elif has_colon > -1:
        page = url[has_colon + 1:]
    else:
        page = url
    page = page.split("/")[0].split(":")[0].lower()

    # extract domain from base url
    base_double_slash = base_url.find("//")
    if base_double_slash > -1:
        base_url = base_url[base_double_slash + 2:]
    else:
        base_has_colon = base_url.find(":")
        if base_has_colon > -1:
            base_url = base_url[base_has_colon + 1:]
    base_url = base_url.split("/")[0].split(":")[0].lower()

    # add any external links to the set of external links
    if page != base_url:
        external_links.add(url)
        return True

    return False


def crawl_link(browser, url, base_url, discovered_urls, external_links, valid_pages):
    """
    This function crawls the target website starting from the page the browser is currently on.
    Any linked pages are also crawled. If a page has already been crawled, or is not on the
    target website, it is not crawled.
    :param browser: the MechanicalSoup stateful browser for interacting with the website
    :param url: the url of the page being crawled
    :param base_url: the base url of the website being fuzzed
    :param discovered_urls: the set of already discovered urls
    :param external_links: the set of previously found external links
    :param valid_pages: the dictionary of valid pages
    :return: None
    """
    if browser.page is None:
        return
    if url in valid_pages:
        return
    # output the current url and add it to the dictionary of valid pages
    print(url)
    valid_pages[browser.url] = [browser.page.title]
    # find all pages that are linked to on this page
    links = browser.page.find_all('a')
    not_yet_crawled = []
    # loop through the links found on the current page and add any new links to a list
    for link in links:
        attrs = link.attrs
        # skip elements that do not link to other pages
        if "href" not in attrs.keys():
            continue
        link_url = attrs["href"]
        # skip already discovered links and external links
        if (link_url in discovered_urls) or is_external(link_url, base_url, external_links):
            continue
        # add this link to the set of discovered urls
        discovered_urls.add(link_url)
        # avoid logging out
        if "logout" in link_url:
            continue
        # add the current link to the set of links that have not been crawled
        not_yet_crawled.append(link)

    # crawl each page in the set of links that have not been crawled
    current_page = browser.url
    for link in not_yet_crawled:
        browser.open(current_page)
        response = browser.follow_link(link)
        if response.status_code != 404:
            url = browser.get_url()
            crawl_link(browser, url, base_url, discovered_urls, external_links, valid_pages)


def page_discovery(browser, base_url, options):
    """
    This function handles crawling and guessing pages.
    :param browser: the MechanicalSoup stateful browser for interacting with the website
    :param base_url: the base url of the website being fuzzed
    :param options: the dictionary of parsed command line options
    :return: the browser, set of discovered urls, set of external links found, and the dictionary of valid pages
    """
    print_title("Links Discovered:")
    # create a set of discovered urls
    discovered_urls = set()
    # avoid turning on the php intrusion detection system
    discovered_urls.add("?phpids=on")
    # create a dictionary of valid pages
    valid_pages = {}
    # create a set of external links found
    external_links = set()
    # crawl the initial url given
    crawl_link(browser, base_url, base_url, discovered_urls, external_links, valid_pages)
    print("-" * 45)
    print("\n" + ("#" * 130))
    # guess pages
    print_title("Pages Successfully Guessed:")
    guess_pages(browser, base_url, discovered_urls, external_links, options, valid_pages)
    print("-" * 27)
    print("\n" + ("#" * 130))
    return browser, discovered_urls, external_links, valid_pages


def check_for_sanitization(vector, response, sanitized_chars):
    """
    A helper method for checking if a response contains the current vector with data that should have been sanitized.
    :param vector: the current fuzzing vector
    :param response: the response from the browser
    :param sanitized_chars: the set of characters that should be sanitized by the website
    :return: True if the response contains the current vector with data that should have been sanitized, False otherwise
    """
    for char in sanitized_chars:
        if (char in vector) and (vector in response.text):
            return True

    return False


def check_for_sensitive_data(response, sensitive):
    """
    A helper method for checking if a response contains sensitive data.
    :param response: the response from the browser
    :param sensitive: the set of sensitive data
    :return: True if the response contains sensitive data, False otherwise
    """
    response_text = response.text
    for element in sensitive:
        if element in response_text:
            return True

    return False


def check_for_delayed_response(response_time, slow):
    """
    A helper method for checking if a response took long than the defined threshold.
    :param response_time: the response time for loading the page
    :param slow: the number of milliseconds after which a response is considered "slow"
    :return: True if the response took more than slow milliseconds, False otherwise
    """
    if (response_time * 1000) > slow:
        return True

    return False


def get_http_code_message(http_code):
    """
    A helper method for getting a human-readable HTTP status code message.
    :param http_code: the HTTP status code
    :return: a human-readable HTTP status code message
    """
    msg_dict = {
        # Information responses:
        100: "Continue",
        101: "Switching Protocols",
        102: "Processing (WebDAV)",
        103: "Early Hints",

        # Successful responses:
        200: "OK",
        201: "Created",
        202: "Accepted",
        203: "Non-Authoritative Information",
        204: "No Content",
        205: "Reset Content",
        206: "Partial Content",
        207: "Multi-Status (WebDAV)",
        208: "Already Reported (WebDAV)",
        226: "IM Used (HTTP Delta encoding)",

        # Redirection messages:
        300: "Multiple Choice",
        301: "Moved Permanently",
        302: "Found",
        303: "See Other",
        304: "Not Modified",
        305: "Use Proxy",
        306: "unused",
        307: "Temporary Redirect",
        308: "Permanent Redirect",

        # Client error responses:
        400: "Bad Request",
        401: "Unauthorized",
        402: "Payment Required",
        403: "Forbidden",
        404: "Not Found",
        405: "Method Not Allowed",
        406: "Not Acceptable",
        407: "Proxy Authentication Required",
        408: "Request Timeout",
        409: "Conflict",
        410: "Gone",
        411: "Length Required",
        412: "Precondition Failed",
        413: "Payload Too Large",
        414: "URI Too Long",
        415: "Unsupported Media Type",
        416: "Range Not Satisfiable",
        417: "Expectation Failed",
        418: "I'm a teapot",
        421: "Misdirected Request",
        422: "Unprocessable Entity (WebDAV)",
        423: "Locked (WebDAV)",
        424: "Failed Dependency (WebDAV)",
        425: "Too Early",
        426: "Upgrade Required",
        428: "Precondition Required",
        429: "Too Many Requests",
        431: "Request Header Fields Too Large",
        451: "Unavailable For Legal Reasons",

        # Server error responses:
        500: "Internal Server Error",
        501: "Not Implemented",
        502: "Bad Gateway",
        503: "Service Unavailable",
        504: "Gateway Timeout",
        505: "HTTP Version Not Supported",
        506: "Variant Also Negotiates",
        507: "Insufficient Storage (WebDAV)",
        508: "Loop Detected (WebDAV)",
        510: "Not Extended",
        511: "Network Authentication Required"
    }

    message = str(http_code) + "{} for "
    if 100 <= http_code <= 199:
        message = "Informational response " + message
    elif 200 <= http_code <= 299:
        message = "Successful response " + message
    elif 300 <= http_code <= 399:
        message = "Redirection response " + message
    elif 400 <= http_code <= 499:
        message = "Client error response " + message
    elif 500 <= http_code <= 599:
        message = "Server error response " + message

    if http_code in msg_dict:
        message = message.format(" " + msg_dict[http_code])

    return message


def check_http_response_code(response):
    """
    A helper method for checking the HTTP status code of a response.
    :param response: the response from the browser
    :return: True if the HTTP status code is not 200, False otherwise
    """
    if response.status_code != 200:
        spacer = 10 * "-"
        print(spacer + "NON 200 HTTP STATUS CODE" + spacer)
        message = get_http_code_message(response.status_code)
        print(message + response.url + "\n")
        return True

    return False


def run_checks(vector, vector_type, target, response, response_time, test_results: TestResults, check_against: list):
    """
    A helper method that handles running vulnerability tests.
    :param vector: the current fuzzing vector
    :param vector_type: the category of the current vector
    :param target: the page being fuzzed
    :param response: the response from the browser
    :param test_results: a TestResults object that test results are added to
    :param check_against: a list containing the sets of elements to check responses against
    :return: None
    """
    vulnerabilities = []
    sensitive, sanitized_chars, slow = check_against
    if check_for_sanitization(vector, response, sanitized_chars):
        test_results.increment("Unsanitized input")
        vulnerabilities.append("Unsanitized input")
    if check_for_sensitive_data(response, sensitive):
        test_results.increment("Sensitive data leaked")
        vulnerabilities.append("Sensitive data leaked")
    if check_for_delayed_response(response_time, slow):
        test_results.increment("Delayed response")
        vulnerabilities.append("Delayed response")
    if check_http_response_code(response):
        test_results.increment("HTTP response code ")
        vulnerabilities.append("HTTP response code " + str(response.status_code))

    if len(vulnerabilities) > 0:
        test_results.increment(vector_type)
        test_results.add_page(target, [vector_type, vulnerabilities])


def test_url_parameters(browser, vectors, parsed_urls, check_against):
    """
    This function handles fuzzing url parameters on each discovered page.
    :param browser: the MechanicalSoup stateful browser for interacting with the website
    :param vectors: the dictionary of vectors
    :param parsed_urls: the dictionary of parsed urls
    :param check_against: a list containing the sets of elements to check responses against
    :return: a TestResults object containing the results of fuzzing url parameters on each discovered page
    """
    url_results = TestResults()
    for url in parsed_urls:
        # if the url has no input parameters, skip it
        if len(parsed_urls[url]) < 2:
            continue
        page_url = parsed_urls[url][0]
        params = parsed_urls[url][1:]
        for param in params:
            param = param.split("=")
            param = "?" + param[0] + "="
            for vector in vectors:
                target = page_url + param + vector
                start = time.perf_counter()
                response = browser.open(target)
                response_time = time.perf_counter() - start
                run_checks(vector, vectors[vector], page_url + param, response, response_time, url_results, check_against)

    return url_results


def test_form_parameters(browser, vectors, valid_pages, check_against):
    """
    This function handles fuzzing form parameters on each discovered page.
    :param browser: the MechanicalSoup stateful browser for interacting with the website
    :param vectors: the dictionary of vectors
    :param valid_pages: the dictionary of valid pages
    :param check_against: a list containing the sets of elements to check responses against
    :return: a TestResults object containing the results of fuzzing form parameters on each discovered page
    """
    form_results = TestResults()
    for page in valid_pages:
        # if the page has no form inputs, skip it
        if len(valid_pages[page]) < 2:
            continue
        # get the list of forms on this page
        forms = valid_pages[page][1]
        for i in range(len(forms)):
            # get the current form
            form = forms[i][0]
            # get the current form's inputs
            inputs = forms[i][1]
            for vector in vectors:
                # get the vector type
                vector_type = vectors[vector]
                for inpt in inputs:
                    # open page
                    browser.open(page)
                    # select the current form
                    browser.select_form(form.__copy__())
                    form_input = vector
                    # if the input requires a file, save the vector to a file called "input.html" and pass it in
                    if inpt.attrs.get("type") == "file":
                        f_name = "input.html"
                        with open("input.html", 'w') as f:
                            f.write(vector)
                        form_input = f_name
                    # set the current input to the current vector
                    if "name" in inpt.attrs:
                        browser[inpt.attrs["name"]] = form_input
                    elif "option" in inpt.attrs:
                        # used to set the current input when the input does not have a "name" attribute
                        browser.form.set("option", form_input)
                    # submit the form
                    start = time.perf_counter()
                    response = browser.submit_selected()
                    response_time = time.perf_counter() - start
                    run_checks(vector, vector_type, page, response, response_time, form_results, check_against)

    return form_results


def test_cookies(browser, vectors, cookies, base_url):
    """
    This function handles fuzzing website cookies.
    :param browser: the MechanicalSoup stateful browser for interacting with the website
    :param vectors: the dictionary of vectors
    :param cookies: the set of cookies
    :param base_url: the base url of the website being fuzzed
    :return: the dictionary of the results of fuzzing the cookies
    """
    cookie_results = {}
    browser.open(base_url)
    # create a copy of the current cookiejar
    cookiejar = browser.get_cookiejar().copy()
    for cookie in cookies:
        for vector in vectors:
            # update cookie
            browser.session.cookies.set(cookie.name, None)
            browser.session.cookies.set(cookie.name, vector, domain=cookie.domain, path=cookie.path)
            browser.open(base_url)
            if browser.get_cookiejar() != cookiejar:
                for new_cookie in browser.get_cookiejar():
                    old_cookie_value = cookiejar.get(new_cookie.name)
                    if new_cookie.value != old_cookie_value:
                        if new_cookie.name not in cookie_results:
                            cookie_results[new_cookie.name] = (old_cookie_value, new_cookie.value)
            # reset cookies
            browser.session.cookies = cookiejar.copy()

    return cookie_results


def read_file(file_name):
    """
    A helper method for reading in a file, and returning a set containing the contents of said file.
    :param file_name: the file to be read
    :return: a set containing the contents of the file
    """
    contents = set()
    with open(file_name) as f:
        for line in f:
            line = line.strip()
            contents.add(line)
    return contents


def read_vectors(file_name):
    """
    A helper method for reading in a file of vectors for fuzzing, and returning a dictionary that maps
    each vector to the type of vulnerability it suggests.
    :param file_name: the file contaminating the vectors
    :return: the dictionary of vectors
    """
    vectors = {}
    category = None
    with open(file_name) as f:
        for line in f:
            line = line.strip()
            if line == "":
                continue
            if "CATEGORY:" in line:
                line = line.split(":")
                category = line[1].strip()
                continue
            vectors[line] = category
    return vectors


def print_test_results(test_results, title_str):
    """
    A helper method for printing a page url, along with which vector types suggested a vulnerability.
    :param test_results: the test results to be printed
    :param title_str: the title to be printed
    :return: None
    """
    print_title(title_str)
    pages = test_results.get_pages()
    for page in pages:
        print(page)
        for vuln in pages[page]:
            print("\t" + str(vuln) + " vector revealed: " + ", ".join(pages[page][vuln]))
        print()
    print("#" * 130)


def print_overall_results(overall_results):
    """
    A helper method for printing the overall results of fuzzing the target website.
    :param overall_results: a TestResults object containing the overall results from fuzzing the website
    :return:
    """
    print_title("Overall test results:")
    counts = overall_results.get_counts()
    num_of = "Number of {}: "
    if "Unsanitized input" in counts:
        print(num_of.format("unsanitized inputs") + str(counts.pop("Unsanitized input")))
    if "Sensitive data leaked" in counts:
        print(num_of.format("sensitive data leaks") + str(counts.pop("Sensitive data leaked")))
    if "Delayed response" in counts:
        print(num_of.format("possible DOS vulnerabilities") + str(counts.pop("Delayed response")))
    if "HTTP response code " in counts:
        print(num_of.format("HTTP response code errors") + str(counts.pop("HTTP response code ")))

    for elem in counts:
        print(elem + " vectors were responsible for finding " + str(counts[elem]) + " potential vulnerabilities.")


def check_remaining_pages(browser, overall_results, valid_pages, check_against):
    """
    This function handles checking for sensitive data and delayed responses on each discovered page without any inputs.
    :param browser: the MechanicalSoup stateful browser for interacting with the website
    :param overall_results: a TestResults object containing the results of fuzzing parameters on each discovered page
    :param valid_pages: the dictionary of valid pages
    :param check_against: a list containing the sets of elements to check responses against
    :return:
    """
    remaining_results = TestResults()
    sensitive, sanitized_chars, slow = check_against
    for page in valid_pages:
        if page in overall_results.get_pages():
            continue
        start = time.perf_counter()
        response = browser.open(page)
        response_time = time.perf_counter() - start
        if check_for_sensitive_data(response, sensitive):
            remaining_results.increment("Sensitive data leaked")
        if check_for_delayed_response(response_time, slow):
            remaining_results.increment("Delayed response")

    return remaining_results


def test_pages(browser, parsed_urls, base_url, valid_pages, cookies, options):
    """
    This function handles testing every discovered input using the list of vectors provided on the command line.
    :param browser: the MechanicalSoup stateful browser for interacting with the website
    :param parsed_urls: the dictionary of parsed urls
    :param base_url: the base url of the website being fuzzed
    :param valid_pages: the dictionary of valid pages
    :param cookies: the set of cookies
    :param options: the dictionary of parsed command line options
    :return: None
    """
    # read in vectors
    vectors = read_vectors(options[VECTORS])
    # read in sensitive data list
    sensitive = read_file(options[SENSITIVE])
    # set characters that should be sanitized
    if SANITIZED_CHARS in options:
        # read in characters that should be sanitized
        sanitized_chars = read_file(options[SANITIZED_CHARS])
    else:
        # set to default characters that should be sanitized
        sanitized_chars = {"<", ">"}
    # the number of milliseconds after which a response is considered "slow"
    if SLOW in options:
        # set slow to the response time given on the command line
        slow = options[SLOW]
    else:
        # set slow to the default "slow" response time
        slow = 500
    # put the values to check responses against into a list to simplify passing them to other functions
    check_against = [sensitive, sanitized_chars, slow]
    print("\n")

    # test vectors against urls with input parameters
    url_results = test_url_parameters(browser, vectors, parsed_urls, check_against)

    # test vectors against pages with form parameters
    form_results = test_form_parameters(browser, vectors, valid_pages, check_against)

    # test vectors against cookies
    cookie_results = test_cookies(browser, vectors, cookies, base_url)

    overall_results = url_results + form_results
    # check all remaining pages
    overall_results = overall_results + check_remaining_pages(browser, overall_results, valid_pages, check_against)

    # print test results
    print("#" * 130)
    print_test_results(url_results, "Pages with vulnerable URL parameters:")
    print_test_results(form_results, "Pages with vulnerable form parameters:")
    print_title("Cookie changes when set to vectors:")
    for name in cookie_results:
        print(name + ":\n\t" + cookie_results[name][0] + " --> " + cookie_results[name][1] + "\n")
    print("#" * 130)
    print_overall_results(overall_results)


def fuzzer(command, url, options):
    """
    Begin fuzzing the web application found at the given url.
    :param command: the command given on the command line (discover or test)
    :param url: the URL of the web application
    :param options: the dictionary of parsed command line options
    :return: None
    """
    if "--custom-auth" in options.keys():
        print("USING DVWA CUSTOM AUTH")
        print("CHANGING SECURITY TO LOW")
        browser = custom_auth(url)
    else:
        browser = mechanicalsoup.StatefulBrowser(user_agent='MechanicalSoup')
        browser.open(url)

    # discover is run in both discover mode and test mode
    print_title("BEGINNING DISCOVERY")
    # start page discovery
    browser, discovered_urls, external_links, valid_pages = page_discovery(browser, url, options)
    # start input discovery
    browser, parsed_urls, valid_pages, cookies = input_discovery(browser, valid_pages)
    # run test mode
    if command == Command.TEST:
        print("\n\n" + ("#" * 130))
        print(("#" * 130) + "\n")
        print_title("BEGINNING TESTS")
        test_pages(browser, parsed_urls, url, valid_pages, cookies, options)


def process_command_line_input():
    """
    Validate and parse the command line input.
    :return: the command given on the command line and a dictionary of the parsed options,
             or None if the command line input is invalid
    """
    # check if there are enough command line arguments
    if len(sys.argv) < 3:
        return error("not enough command line arguments")

    # ensure only one command is specified
    if "discover" in sys.argv and "test" in sys.argv:
        return error("discover and test are mutually exclusive options")

    # set command and parse options
    if sys.argv[1] == "discover":
        print("RUNNING FUZZER IN DISCOVER MODE")
        command = Command.DISCOVER
        options = parse_options(DISCOVER_OPTIONS, command)
    elif sys.argv[1] == "test":
        print("RUNNING FUZZER IN TEST MODE")
        command = Command.TEST
        options = parse_options(TEST_OPTIONS, command)
    else:
        error("no command specified")
        print_commands()
        return
    if options is None:
        return None

    return [command, options]


def main():
    """
    Process the command line input, set the web application URL, and begin fuzzing.
    :return: None
    """
    # process the command line input
    processed_input = process_command_line_input()
    if processed_input is None:
        return None
    command = processed_input[0]
    options = processed_input[1]

    # set url
    url = sys.argv[2]

    # begin fuzzing
    fuzzer(command, url, options)


if __name__ == '__main__':
    main()
