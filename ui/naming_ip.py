import shodan
import ipaddress
import random
import textblob
from wonderwords import RandomWord


shodan_api_key = "Ps5jkjkyUqT6xjkYg5ePMF5kQ2cVH9ec"

api = shodan.Shodan(shodan_api_key)

def generate_dest_random():
    prefixes = ["Local", "Internal", "Private", "Home"]
    suffixes = ["System", "Device", "Server", "Host"]
    return f"{random.choice(prefixes)} {random.choice(suffixes)}"

r = RandomWord()

def generate_source_random2():
    attempts = 0
    while (attempts <= 20):
        word = r.word(include_parts_of_speech=["adjectives"])

        if (textblob.TextBlob(word).sentiment.polarity > 0.5):
            return word.capitalize() + " Badger"
        else:
            attempts +=1
    # Fallback to pre-made list if nothing found
    fallback = ["Swift", "Bright", "Noble", "Strong", "Wise"]
    return random.choice(fallback) + " Badger"


def get_destination_info(ip_address):
    try:
        host = api.host(ip_address)
        
        print(f"\nIP: {host['ip_str']}")
        dest_name = host.get('org', 'N/A')
        print(f"Organization: {host.get('org', 'N/A')}")
        print(f"Operating System: {host.get('os', 'N/A')}")
        
        # Print all open ports
        print("[+] Open Ports:")
        for item in host['data']:
            print(f"    Port {item['port']}: {item['transport']}")
            
        return dest_name
        
    except shodan.APIError as e:
        if ipaddress.ip_address(ip_address).is_private:
            dest_name = generate_dest_random()
            return dest_name
            
        else:
            print(f"[-] Error: {e}")
        return None


#Test if it works by calling for 3 test IPs
"""get_destination_info("10.140.145.27")  
get_destination_info("8.8.8.8")  # Google DNS - usually has data
get_destination_info("1.1.1.1")      # Cloudflare DNS
get_destination_info("45.33.32.156") # Scanme.nmap.org - intentionally scannable
"""

