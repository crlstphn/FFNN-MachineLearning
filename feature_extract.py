import re
import urllib.parse
import requests
import socket
import whois
import dns.resolver
from bs4 import BeautifulSoup
import datetime

# Function to count the occurrences of a character in a string


def count_char_occurrences(string, char):
    return string.count(char)

# Function to check if a domain name is an IP address


def is_ip_address(domain):
    try:
        socket.inet_aton(domain)
        return True
    except socket.error:
        return False

# Function to check if an email address is present in a string


def is_email_in_string(string):
    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b'
    return re.search(email_pattern, string) is not None

# Function to extract features from a URL


def extract_features_from_url(url):
    # Parse the URL
    parsed_url = urllib.parse.urlparse(url)

    # Extract features related to the URL itself
    qty_dot_url = count_char_occurrences(url, '.')
    qty_hyphen_url = count_char_occurrences(url, '-')
    qty_underline_url = count_char_occurrences(url, '_')
    qty_slash_url = count_char_occurrences(url, '/')
    qty_questionmark_url = count_char_occurrences(url, '?')
    qty_equal_url = count_char_occurrences(url, '=')
    qty_at_url = count_char_occurrences(url, '@')
    qty_and_url = count_char_occurrences(url, '&')
    qty_exclamation_url = count_char_occurrences(url, '!')
    qty_space_url = count_char_occurrences(url, ' ')
    qty_tilde_url = count_char_occurrences(url, '~')
    qty_comma_url = count_char_occurrences(url, ',')
    qty_plus_url = count_char_occurrences(url, '+')
    qty_asterisk_url = count_char_occurrences(url, '*')
    qty_hashtag_url = count_char_occurrences(url, '#')
    qty_dollar_url = count_char_occurrences(url, '$')
    qty_percent_url = count_char_occurrences(url, '%')
    qty_tld_url = parsed_url.netloc.split('.')[-1]
    length_url = len(url)

    # Extract features related to the domain
    qty_dot_domain = count_char_occurrences(parsed_url.netloc, '.')
    qty_hyphen_domain = count_char_occurrences(parsed_url.netloc, '-')
    qty_underline_domain = count_char_occurrences(parsed_url.netloc, '_')
    qty_slash_domain = count_char_occurrences(parsed_url.netloc, '/')
    qty_questionmark_domain = count_char_occurrences(parsed_url.netloc, '?')
    qty_equal_domain = count_char_occurrences(parsed_url.netloc, '=')
    qty_at_domain = count_char_occurrences(parsed_url.netloc, '@')
    qty_and_domain = count_char_occurrences(parsed_url.netloc, '&')
    qty_exclamation_domain = count_char_occurrences(parsed_url.netloc, '!')
    qty_space_domain = count_char_occurrences(parsed_url.netloc, ' ')
    qty_tilde_domain = count_char_occurrences(parsed_url.netloc, '~')
    qty_comma_domain = count_char_occurrences(parsed_url.netloc, ',')
    qty_plus_domain = count_char_occurrences(parsed_url.netloc, '+')
    qty_asterisk_domain = count_char_occurrences(parsed_url.netloc, '*')
    qty_hashtag_domain = count_char_occurrences(parsed_url.netloc, '#')
    qty_dollar_domain = count_char_occurrences(parsed_url.netloc, '$')
    qty_percent_domain = count_char_occurrences(parsed_url.netloc, '%')
    qty_vowels_domain = sum(
        1 for char in parsed_url.netloc if char.lower() in "aeiou")
    domain_length = len(parsed_url.netloc)
    domain_in_ip = is_ip_address(parsed_url.netloc)

    # Send an HTTP request to the URL and measure the response time
    response = None  # Initialize response variable
    try:
        start_time = datetime.datetime.now()
        response = requests.get(url)
        end_time = datetime.datetime.now()
        time_response = (end_time - start_time).total_seconds()
    except requests.exceptions.RequestException:
        time_response = -1  # Set to -1 in case of an error

    # Check if the domain has SPF records
    try:
        spf_records = dns.resolver.query(parsed_url.netloc, 'TXT')
        domain_spf = any('v=spf1' in str(record) for record in spf_records)
    except dns.resolver.NXDOMAIN:
        domain_spf = False
    except dns.resolver.NoAnswer:
        domain_spf = False

    # Check if the domain is in Google's index
    google_url = f"https://www.google.com/search?q=site:{parsed_url.netloc}"
    google_response = requests.get(google_url)
    soup = BeautifulSoup(google_response.text, 'html.parser')
    domain_google_index = "did not match any documents" not in soup.text

    # Extract features related to the path (directory and file)
    path_components = parsed_url.path.split('/')
    qty_dot_directory = sum(count_char_occurrences(component, '.')
                            for component in path_components)
    qty_hyphen_directory = sum(count_char_occurrences(
        component, '-') for component in path_components)
    qty_underline_directory = sum(count_char_occurrences(
        component, '_') for component in path_components)
    qty_slash_directory = sum(count_char_occurrences(
        component, '/') for component in path_components)
    qty_questionmark_directory = sum(count_char_occurrences(
        component, '?') for component in path_components)
    qty_equal_directory = sum(count_char_occurrences(
        component, '=') for component in path_components)
    qty_at_directory = sum(count_char_occurrences(component, '@')
                           for component in path_components)
    qty_and_directory = sum(count_char_occurrences(component, '&')
                            for component in path_components)
    qty_exclamation_directory = sum(count_char_occurrences(
        component, '!') for component in path_components)
    qty_space_directory = sum(count_char_occurrences(
        component, ' ') for component in path_components)
    qty_tilde_directory = sum(count_char_occurrences(
        component, '~') for component in path_components)
    qty_comma_directory = sum(count_char_occurrences(
        component, ',') for component in path_components)
    qty_plus_directory = sum(count_char_occurrences(
        component, '+') for component in path_components)
    qty_asterisk_directory = sum(count_char_occurrences(
        component, '*') for component in path_components)
    qty_hashtag_directory = sum(count_char_occurrences(
        component, '#') for component in path_components)
    qty_dollar_directory = sum(count_char_occurrences(
        component, '$') for component in path_components)
    qty_percent_directory = sum(count_char_occurrences(
        component, '%') for component in path_components)
    directory_length = sum(len(component) for component in path_components)

    qty_dot_file = count_char_occurrences(parsed_url.path, '.')
    qty_hyphen_file = count_char_occurrences(parsed_url.path, '-')
    qty_underline_file = count_char_occurrences(parsed_url.path, '_')
    qty_slash_file = count_char_occurrences(parsed_url.path, '/')
    qty_questionmark_file = count_char_occurrences(parsed_url.path, '?')
    qty_equal_file = count_char_occurrences(parsed_url.path, '=')
    qty_at_file = count_char_occurrences(parsed_url.path, '@')
    qty_and_file = count_char_occurrences(parsed_url.path, '&')
    qty_exclamation_file = count_char_occurrences(parsed_url.path, '!')
    qty_space_file = count_char_occurrences(parsed_url.path, ' ')
    qty_tilde_file = count_char_occurrences(parsed_url.path, '~')
    qty_comma_file = count_char_occurrences(parsed_url.path, ',')
    qty_plus_file = count_char_occurrences(parsed_url.path, '+')
    qty_asterisk_file = count_char_occurrences(parsed_url.path, '*')
    qty_hashtag_file = count_char_occurrences(parsed_url.path, '#')
    qty_dollar_file = count_char_occurrences(parsed_url.path, '$')
    qty_percent_file = count_char_occurrences(parsed_url.path, '%')
    file_length = len(parsed_url.path)

    # Extract features related to query parameters
    query_parameters = urllib.parse.parse_qs(parsed_url.query)
    qty_dot_params = sum(count_char_occurrences(param, '.')
                         for param in query_parameters)
    qty_hyphen_params = sum(count_char_occurrences(param, '-')
                            for param in query_parameters)
    qty_underline_params = sum(count_char_occurrences(
        param, '_') for param in query_parameters)
    qty_slash_params = sum(count_char_occurrences(param, '/')
                           for param in query_parameters)
    qty_questionmark_params = sum(count_char_occurrences(
        param, '?') for param in query_parameters)
    qty_equal_params = sum(count_char_occurrences(param, '=')
                           for param in query_parameters)
    qty_at_params = sum(count_char_occurrences(param, '@')
                        for param in query_parameters)
    qty_and_params = sum(count_char_occurrences(param, '&')
                         for param in query_parameters)
    qty_exclamation_params = sum(count_char_occurrences(
        param, '!') for param in query_parameters)
    qty_space_params = sum(count_char_occurrences(param, ' ')
                           for param in query_parameters)
    qty_tilde_params = sum(count_char_occurrences(param, '~')
                           for param in query_parameters)
    qty_comma_params = sum(count_char_occurrences(param, ',')
                           for param in query_parameters)
    qty_plus_params = sum(count_char_occurrences(param, '+')
                          for param in query_parameters)
    qty_asterisk_params = sum(count_char_occurrences(param, '*')
                              for param in query_parameters)
    qty_hashtag_params = sum(count_char_occurrences(param, '#')
                             for param in query_parameters)
    qty_dollar_params = sum(count_char_occurrences(param, '$')
                            for param in query_parameters)
    qty_percent_params = sum(count_char_occurrences(param, '%')
                             for param in query_parameters)
    params_length = sum(len(param) for param in query_parameters)
    tld_present_params = qty_tld_url in query_parameters

    # count number of params in url
    qty_params = len(query_parameters)

    # Check if the URL is shortened (e.g., using a URL shortening service)
    url_shortened = len(parsed_url.netloc) < 10

    # Send an HTTP request to the URL and measure the response time
    try:
        start_time = datetime.datetime.now()
        response = requests.get(url)
        end_time = datetime.datetime.now()
        time_response = (end_time - start_time).total_seconds()
    except requests.exceptions.RequestException:
        time_response = -1  # Set to -1 in case of an error

    # Get ASN (Autonomous System Number) information for the IP address
    if domain_in_ip:
        try:
            ip_info = socket.gethostbyname(parsed_url.netloc)
            asn_ip = whois.whois(ip_info).asn
        except (socket.gaierror, AttributeError):
            asn_ip = ""
    else:
        asn_ip = ""

    # Get domain registration information
    try:
        domain_info = whois.whois(parsed_url.netloc)
        time_domain_activation = (
            domain_info.creation_date - datetime.datetime.now()).days
        time_domain_expiration = (
            domain_info.expiration_date - datetime.datetime.now()).days
    except (AttributeError, TypeError):
        time_domain_activation = -1
        time_domain_expiration = -1

    # Get DNS information for the domain
    try:
        dns_info = dns.resolver.query(parsed_url.netloc, 'NS')
        qty_nameservers = len(dns_info)
    except dns.resolver.NXDOMAIN:
        qty_nameservers = 0
    except dns.exception.DNSException:
        qty_nameservers = -1

    # Get MX (Mail Exchange) server information for the domain
    try:
        mx_info = dns.resolver.query(parsed_url.netloc, 'MX')
        qty_mx_servers = len(mx_info)
    except dns.resolver.NXDOMAIN:
        qty_mx_servers = 0
    except dns.exception.DNSException:
        qty_mx_servers = -1

    # Get TTL (Time to Live) value for the hostname
    try:
        resolver = dns.resolver.Resolver()
        ttl_info = resolver.resolve(parsed_url.netloc, 'A')
        ttl_hostname = ttl_info.rrset.ttl
    except dns.resolver.NXDOMAIN:
        ttl_hostname = -1
    except dns.exception.DNSException:
        ttl_hostname = -1

    # Check if the website uses TLS/SSL
    try:
        tls_ssl_certificate = bool(parsed_url.netloc.startswith("https"))
    except AttributeError:
        tls_ssl_certificate = False

    # Check for redirects
    try:
        redirects = len(response.history)
        qty_redirects = redirects - 1 if redirects > 0 else 0
    except (AttributeError, TypeError):
        qty_redirects = -1

    # Combine all features into a dictionary
    features = [
        qty_dot_url,
        qty_hyphen_url,
        qty_underline_url,
        qty_slash_url,
        qty_questionmark_url,
        qty_equal_url,
        qty_at_url,
        qty_and_url,
        qty_exclamation_url,
        qty_space_url,
        qty_tilde_url,
        qty_comma_url,
        qty_plus_url,
        qty_asterisk_url,
        qty_hashtag_url,
        qty_dollar_url,
        qty_percent_url,
        len(qty_tld_url),
        length_url,
        qty_dot_domain,
        qty_hyphen_domain,
        qty_underline_domain,
        qty_slash_domain,
        qty_questionmark_domain,
        qty_equal_domain,
        qty_at_domain,
        qty_and_domain,
        qty_exclamation_domain,
        qty_space_domain,
        qty_tilde_domain,
        qty_comma_domain,
        qty_plus_domain,
        qty_asterisk_domain,
        qty_hashtag_domain,
        qty_dollar_domain,
        qty_percent_domain,
        qty_vowels_domain,
        domain_length,
        int(domain_in_ip),
        len(parsed_url.netloc),
        qty_dot_directory,
        qty_hyphen_directory,
        qty_underline_directory,
        qty_slash_directory,
        qty_questionmark_directory,
        qty_equal_directory,
        qty_at_directory,
        qty_and_directory,
        qty_exclamation_directory,
        qty_space_directory,
        qty_tilde_directory,
        qty_comma_directory,
        qty_plus_directory,
        qty_asterisk_directory,
        qty_hashtag_directory,
        qty_dollar_directory,
        qty_percent_directory,
        directory_length,
        qty_dot_file,
        qty_hyphen_file,
        qty_underline_file,
        qty_slash_file,
        qty_questionmark_file,
        qty_equal_file,
        qty_at_file,
        qty_and_file,
        qty_exclamation_file,
        qty_space_file,
        qty_tilde_file,
        qty_comma_file,
        qty_plus_file,
        qty_asterisk_file,
        qty_hashtag_file,
        qty_dollar_file,
        qty_percent_file,
        file_length,
        qty_dot_params,
        qty_hyphen_params,
        qty_underline_params,
        qty_slash_params,
        qty_questionmark_params,
        qty_equal_params,
        qty_at_params,
        qty_and_params,
        qty_exclamation_params,
        qty_space_params,
        qty_tilde_params,
        qty_comma_params,
        qty_plus_params,
        qty_asterisk_params,
        qty_hashtag_params,
        qty_dollar_params,
        qty_percent_params,
        params_length,
        int(tld_present_params),
        qty_params,
        int(is_email_in_string(url)),
        time_response,
        int(domain_spf),
        asn_ip,
        time_domain_activation,
        time_domain_expiration,
        int(domain_in_ip),
        qty_nameservers,
        qty_mx_servers,
        ttl_hostname,
        int(tls_ssl_certificate),
        qty_redirects,
        int(domain_google_index),
        int(domain_google_index),
        int(url_shortened),
    ]

    features = [0 if feature == '' else feature for feature in features]

    return features


# Example usage:
new_url = "http://horizonsgallery.com/js/bin/ssl1/_id/www.paypal.com/fr/cgi-bin/webscr/cmd=_registration-run/login.php?cmd=_login-run&amp;dispatch=1471c4bdb044ae2be9e2fc3ec514b88b1471c4bdb044ae2be9e2fc3ec514b88b"
new_features = extract_features_from_url(new_url)
print(new_features)
