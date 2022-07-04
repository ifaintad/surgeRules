import rulesets
import itertools
import requests
from requests.adapters import HTTPAdapter, Retry
from urllib.parse import urlsplit
import os

DEBUG = False


def debug_print(s):
    if not DEBUG:
        return
    print(s)


def get_rule_value(rule):
    try:
        return rule.split(",")[1].split("//")[0].split("#")[0].strip()
    except KeyError:
        return rule.split("//")[0].split("#")[0].strip()


FORCE_DOMAIN_KEYWORDS = {
    "google", "blogspot", "facebook", "pinterest",
    "googleapis"}


TOP_LEVEL_DOMAINS = {
    "au",
    "de",
    "eu",
    "fr",
    "jp",
    "my",
    "sg",
    "tw",
    "uk"
}


def is_banned_top_level_domains(url):
    for suffix in [f'.{d}' for d in TOP_LEVEL_DOMAINS]:
        if url.endswith(suffix):
            return True
    return False


def is_of_domain(url, domain_set):
    for suffix in [f'{s.strip().rstrip(".")}.' for s in domain_set]:
        if url.startswith(suffix):
            return True

    for part in [f'.{s.strip().lstrip(".").rstrip(".")}.' for s in domain_set]:
        if part in url:
            return True

    return False


class RuleSets:
    def __init__(self, rule_dicts, has_prefix=True, n_retries=10):
        self.rule_items = [
            RuleItem(n_retries=n_retries, **rule_dict) for rule_dict in rule_dicts]
        self.rule_set = set(itertools.chain(
            *[rule_item.list for rule_item in self.rule_items]))

        self.domain_keyword_set = set(itertools.chain(
            *[list(rule_item.domain_keywords) for rule_item in self.rule_items]))
        self.has_prefix = has_prefix
        self.update_rule_set()

    def get_all_urls(self):
        ret = []
        for r in self.rule_set:
            r_split = r.split(",")
            _type = r_split[0]
            assert _type.strip() in [
                "DOMAIN-SUFFIX", "DOMAIN", "IP-CIDR", "DOMAIN-KEYWORD",
                "USER-AGENT", "SRC-IP-CIDR", "DST-PORT", "SRC-PORT",
                "IP-CIDR6", "PROCESS-NAME"], r
            ret.append(get_rule_value(r))

        return set(ret)

    def update_rule_set(self):
        for rule in list(self.rule_set):
            if rule.startswith("DOMAIN-SUFFIX,"):
                value = get_rule_value(rule)
                if is_of_domain(
                        value,
                        self.domain_keyword_set.union(self.domain_keyword_set)):
                    self.rule_set.remove(rule)

    def update_items(self):
        for item in self.rule_items:
            item.list = item.update_list(self.rule_set)

    def write_all_rules(self, output_dir):
        self.update_items()
        for item in self.rule_items:
            item.write_rules(output_dir)


class RuleItem:
    def __init__(self, url, file_name=None, n_retries=10, has_prefix=True, domain_keywords=None,
                 filter_top_level_banned_domain=False):
        self.session = requests.session()
        self.n_retries = n_retries
        self.retries = Retry(
            total=n_retries,
            backoff_factor=0.1,
            status_forcelist=[500, 502, 503, 504])
        self.filter_top_level_banned_domain = filter_top_level_banned_domain

        self.file_name = file_name or urlsplit(url).path.split("/")[-1]
        self.url = url
        self.has_prefix = has_prefix

        domain_keywords = domain_keywords or []

        self.domain_keywords = set(domain_keywords)

        self.list = self.get_list()

        self.domain_keywords_readonly = set(self.domain_keywords)

    def get_list(self):
        self.session.mount(self.url, HTTPAdapter(max_retries=self.retries))
        resp = self.session.get(self.url)
        ret = [r.strip() for r in resp.content.decode().split("\n")
               if r.strip() and not r.strip().startswith("#")]

        if not self.has_prefix:
            return ret

        for item in ret:
            if item.startswith("DOMAIN-KEYWORD,"):
                self.domain_keywords.add(get_rule_value(item))

        return ret

    def build_rules(self, exist_rules, unused_domain_keywords, domain_keywords_readonly):
        if self.has_prefix:
            new_rules = []
            for r in self.list:
                if r not in exist_rules:
                    continue

                exist_rules.remove(r)

                if not (r.startswith("DOMAIN-SUFFIX,")
                        or r.startswith("DOMAIN-KEYWORD,")):
                    new_rules.append(r)
                    continue

                url = get_rule_value(r)
                if r.startswith("DOMAIN-KEYWORD"):
                    try:
                        unused_domain_keywords.remove(url)
                    except KeyError:
                        pass
                    else:
                        new_rules.append(r)

                    continue

                if is_of_domain(url, domain_keywords_readonly):
                    continue
                if self.filter_top_level_banned_domain and is_banned_top_level_domains(url):
                    continue
                else:
                    new_rules.append(r)
            return new_rules

        _urls = [u for u in self.list
                 if not is_of_domain(u, domain_keywords_readonly)
                 and not is_banned_top_level_domains(u)]

        rules = [f"DOMAIN-SUFFIX,{url}" for url in _urls]

        return [r for r in rules if r not in exist_rules]

    def update_list(self, exist_rules,
                    unused_domain_keywords=None,
                    domain_keywords_readonly=None):
        unused_domain_keywords = unused_domain_keywords or self.domain_keywords
        domain_keywords_readonly = domain_keywords_readonly or self.domain_keywords_readonly

        rules = self.build_rules(set(exist_rules), unused_domain_keywords, domain_keywords_readonly)

        self.list = list(rules)
        return self.list

    def write_rules(self, output_dir):
        rule_list = self.list[:]
        rule_list.insert(0, f"# Based on {self.url}")

        rule_list.extend(
            [f"DOMAIN-KEYWORD,{url}" for url in self.domain_keywords])

        if self.filter_top_level_banned_domain:
            rule_list.extend(
                [f"DOMAIN-SUFFIX,.{tld}" for tld in TOP_LEVEL_DOMAINS])

        rule_list = sorted(list(set(rule_list)))

        with open(os.path.join(output_dir, self.file_name), "w") as f:
            f.write("\n".join(sorted(rule_list)))


class SurgeRules:
    def __init__(self, output_dir, n_retries=10):
        self.n_retries = n_retries
        self.output_dir = output_dir

    def get_all_rule_set(self):
        banned_rule_set = RuleSets(
            rule_dicts=[rulesets.ADBLOCK, rulesets.ADBLOCK3,
                        rulesets.HIJACKING, rulesets.BAN_PROGRAM_AD],
            n_retries=self.n_retries)

        banned_rule_set.write_all_rules(self.output_dir)

        direct_rule_set = RuleSets(
            rule_dicts=[rulesets.APPLE, rulesets.MICROSOFT,
                        rulesets.DIRECT_LAN, rulesets.DIRECT_CN,
                        rulesets.DIRECT_IP,
                        rulesets.DIRECT_PRIVATE_TRACKER],
            n_retries=self.n_retries)

        direct_rule_set.write_all_rules(self.output_dir)

        proxy_rule_set = RuleSets(
            rule_dicts=[rulesets.YOUTUBE, rulesets.NETFLIX, rulesets.DISNEY_PLUS],
            n_retries=self.n_retries
        )
        proxy_rule_set.write_all_rules(self.output_dir)

        self.build_extra_proxy_list(proxy_rule_set)

    def build_extra_proxy_list(self, proxy_rule_set: RuleSets):
        unused_domain_keywords = FORCE_DOMAIN_KEYWORDS.difference(proxy_rule_set.domain_keyword_set)
        domain_set_used = proxy_rule_set.domain_keyword_set.union(FORCE_DOMAIN_KEYWORDS)
        proxy_ruleset_obj = RuleItem(
            n_retries=self.n_retries, **rulesets.PROXY_RAW_LIST
        )
        proxy_ruleset_obj.update_list(
            proxy_rule_set.rule_set,
            unused_domain_keywords=unused_domain_keywords,
            domain_keywords_readonly=domain_set_used
        )
        proxy_ruleset_obj.write_rules(self.output_dir)


if __name__ == "__main__":
    SurgeRules("publish").get_all_rule_set()
