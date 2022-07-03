import urls
import requests
from requests.adapters import HTTPAdapter, Retry
from urllib.parse import urlsplit
import os

DEBUG = False

OUTPUT_DIR = "publish"


def debug_print(s):
    if not DEBUG:
        return
    print(s)


FORCE_DOMAIN_KEYWORDS = (
    "google", "blogspot", "youtube", "facebook", "pinterest", "googleapis")


def is_of_domain(url):
    for suffix in [f"{s}." for s in FORCE_DOMAIN_KEYWORDS]:
        if url.startswith(suffix):
            return True

    for part in [f".{s}." for s in FORCE_DOMAIN_KEYWORDS]:
        if part in url:
            return True

    return False


class RuleSet:
    def __init__(self, url, file_name=None, n_retries=10, has_rules=True):
        self.session = requests.session()
        self.n_retries = n_retries
        self.retries = Retry(
            total=n_retries,
            backoff_factor=0.1,
            status_forcelist=[500, 502, 503, 504])

        self.file_name = file_name or urlsplit(url).path.split("/")[-1]
        self.url = url
        self.has_rules = has_rules

    def get_list(self):
        self.session.mount(self.url, HTTPAdapter(max_retries=self.retries))
        resp = self.session.get(self.url)
        return [r.strip() for r in resp.content.decode().split("\n")
                if r.strip() and not r.strip().startswith("#")]

    def build_rules(self, rules, exist_urls, unused_domain_keywords: set):
        if self.has_rules:
            new_rules = []
            for r in rules:
                if not (r.startswith("DOMAIN-SUFFIX,")
                        or r.startswith("DOMAIN-KEYWORD,")
                        or r.startswith("DOMAIN,")):
                    new_rules.append(r)
                    continue
                url = r.split(",")[1].split("//")[0].split("#")[0].strip()
                if r.startswith("DOMAIN-KEYWORD"):
                    try:
                        unused_domain_keywords.remove(url)
                    except KeyError:
                        pass
                    else:
                        new_rules.append(r)

                    continue

                if is_of_domain(url):
                    continue
                else:
                    new_rules.append(r)
            return new_rules

        _urls = [u for u in rules if u not in exist_urls and not is_of_domain(u)]

        return [f"DOMAIN-SUFFIX,{url}" for url in _urls]

    def get_rules(self, exist_rule_set, exist_urls=None, unused_domain_keywords=None):
        exist_urls = exist_urls or []
        unused_domain_keywords = unused_domain_keywords or set()
        rules = self.get_list()
        rules = self.build_rules(rules, exist_urls, unused_domain_keywords)

        ret = set(rules).difference(exist_rule_set)
        exist_rule_set.update(ret)
        return list(ret)


class SurgeRules:
    def __init__(self, n_retries=10):
        self.all_ruleset = set()
        self.all_ruleset_urls = set()
        self.n_retries = n_retries
        self.unused_domain_keyword_set = set(FORCE_DOMAIN_KEYWORDS)

    def get_ruleset_urls(self):
        ret = []
        for r in self.all_ruleset:
            r_split = r.split(",")
            _type = r_split[0]
            assert _type.strip() in [
                "DOMAIN-SUFFIX", "DOMAIN", "IP-CIDR", "DOMAIN-KEYWORD",
                "USER-AGENT", "SRC-IP-CIDR", "DST-PORT", "SRC-PORT",
                "IP-CIDR6", "PROCESS-NAME"], r
            _url = r_split[1].split("//")[0].split("#")[0].strip()
            ret.append(_url)

        self.all_ruleset_urls = set(ret)
        return self.all_ruleset_urls

    def get_all_rule_set(self):
        for url in [urls.ADBLOCK,
                    urls.ADBLOCK2,
                    urls.YOUTUBE,
                    urls.NETFLIX,
                    urls.DISNEY_PLUS,
                    urls.APPLE,
                    urls.APPLE_TV,
                    urls.MICROSOFT,
                    urls.DIRECT_CN,
                    urls.DIRECT_IP,
                    urls.DIRECT_LAN,
                    urls.DIRECT_PRIVATE_TRACKER]:
            ruleset_obj = RuleSet(url, n_retries=self.n_retries)
            ruleset = sorted(
                list(ruleset_obj.get_rules(
                    self.all_ruleset,
                    unused_domain_keywords=self.unused_domain_keyword_set)))

            ruleset.insert(0, f"# Based on {ruleset_obj.url}")

            with open(os.path.join(OUTPUT_DIR, ruleset_obj.file_name), "w") as f:
                f.write("\n".join(ruleset))

        self.build_proxy_list()

    def build_proxy_list(self):
        exist_urls = self.get_ruleset_urls()
        proxy_ruleset_obj = RuleSet(
            urls.PROXY_RAW_LIST, file_name="Proxy.list", has_rules=False)
        proxy_ruleset = list(proxy_ruleset_obj.get_rules(
                exist_urls, unused_domain_keywords=self.unused_domain_keyword_set))

        proxy_ruleset.extend(
            [f"DOMAIN-KEYWORD,{url}" for url in self.unused_domain_keyword_set])

        with open(os.path.join(OUTPUT_DIR, proxy_ruleset_obj.file_name), "w") as f:
            f.write("\n".join(sorted(proxy_ruleset)))


if __name__ == "__main__":
    SurgeRules().get_all_rule_set()
