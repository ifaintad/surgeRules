import rulesets
import itertools
import requests
from requests.adapters import HTTPAdapter
from urllib.parse import urlsplit
import os

from check_domains import get_invalid_domains

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
            RuleItem(n_retries=n_retries, **rule_dict)
            for rule_dict in rule_dicts]
        self.rule_set = set(itertools.chain(
            *[rule_item.list for rule_item in self.rule_items]))
        self.rule_set_copy = set(self.rule_set)

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

    def update_items(self, exist_rules=None, invalid_domains=None):
        exist_rules = exist_rules or self.rule_set
        for item in self.rule_items:
            item.update_list(
                exist_rules,
                invalid_domains=invalid_domains)

    def write_all_rules(
            self, output_dir, exist_rules=None, invalid_domains=None):
        exist_rules = exist_rules or self.rule_set
        self.update_items(
            exist_rules, invalid_domains=invalid_domains)
        for item in self.rule_items:
            item.write_rules(output_dir)


class RuleItem:
    def __init__(self, url, file_name=None, n_retries=10, has_prefix=True,
                 domain_keywords=None,
                 filter_top_level_banned_domain=False):
        self.session = requests.session()
        self.n_retries = n_retries
        self.session.mount(url, HTTPAdapter(max_retries=n_retries))
        resp = self.session.get(url)
        self.raw_list = [r.strip() for r in resp.content.decode().split("\n")
                         if r.strip() and not r.strip().startswith("#")]

        self._list = None
        self.filter_top_level_banned_domain = filter_top_level_banned_domain

        self.file_name = file_name or urlsplit(url).path.split("/")[-1]
        self.url = url
        self.has_prefix = has_prefix

        domain_keywords = domain_keywords or []
        self.domain_keywords = set(domain_keywords)

        if has_prefix:
            for item in self.raw_list:
                _url = get_rule_value(item)
                if item.startswith("DOMAIN-KEYWORD,"):
                    self.domain_keywords.add(_url)

        self.domain_keywords_readonly = set(self.domain_keywords)

    @property
    def list(self):
        if self._list is not None:
            return self._list

        self._list = self.raw_list
        return self._list

    @property
    def url_list(self):
        if self.has_prefix:
            ret = [
                get_rule_value(r) for r in self.list
                if r.startswith("DOMAIN-SUFFIX,")]
        else:
            ret = self.raw_list

        return [
            r.lstrip(".").rstrip(".")
            for r in ret
            if (not (r.endswith("-") or r.startswith("-"))
                and "." in r.lstrip(".").rstrip(".")
                and len(r.lstrip(".").rstrip(".")) > 2)
        ]

    def filter_list(self, invalid_domains=None):
        invalid_domains = invalid_domains or set()

        if not self.has_prefix:
            self._list = [
                r for r in self.list if r not in invalid_domains]
            return

        self._list = [
            r for r in self.list
            if not r.startswith("DOMAIN-SUFFIX,") or (
                    r.startswith("DOMAIN-SUFFIX,")
                    and get_rule_value(r) not in invalid_domains)]

    def build_rules(self, exist_rules, unused_domain_keywords,
                    domain_keywords_readonly, invalid_domains=None):

        if invalid_domains:
            self.filter_list(invalid_domains)

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
                if (self.filter_top_level_banned_domain
                        and is_banned_top_level_domains(url)):
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
                    domain_keywords_readonly=None,
                    invalid_domains=None):
        unused_domain_keywords = unused_domain_keywords or self.domain_keywords
        domain_keywords_readonly = (
                domain_keywords_readonly or self.domain_keywords_readonly)
        invalid_domains = invalid_domains or set()

        rules = self.build_rules(exist_rules, unused_domain_keywords,
                                 domain_keywords_readonly, invalid_domains)

        self._list = list(rules)
        return self.list

    def write_rules(self, output_dir):
        rule_list = self.list[:]
        rule_list.insert(0, f"# Based on {self.url}")

        rule_list.extend(
            [f"DOMAIN-KEYWORD,{url}" for url in self.domain_keywords])

        if self.filter_top_level_banned_domain:
            rule_list.extend(
                [f"DOMAIN-SUFFIX,{tld}" for tld in TOP_LEVEL_DOMAINS])

        rule_list = sorted(list(set(rule_list)))

        with open(os.path.join(output_dir, self.file_name), "w") as f:
            f.write("\n".join(sorted(rule_list)))


class SurgeRules:
    def __init__(self, output_dir,
                 banning_rules_dicts,
                 direct_rules_dicts,
                 media_rules_dict,
                 proxy_raw_list_dict,
                 invalid_domains_file_name="invalid.txt",
                 force_update_invalid_domains=False,
                 n_retries=10):
        self.n_retries = n_retries
        self.output_dir = output_dir
        self.banning_rules_dicts = banning_rules_dicts
        self.direct_rules_dicts = direct_rules_dicts
        self.media_rules_dict = media_rules_dict
        self.proxy_raw_list_dict = proxy_raw_list_dict
        try:
            os.makedirs(output_dir, exist_ok=False)
        except OSError:
            pass
        self.invalid_domains_file_path = os.path.join(
            output_dir, invalid_domains_file_name)
        self.force_update_invalid_domains = force_update_invalid_domains

    def get_invalid_domains(self):

        if (not self.force_update_invalid_domains
                and os.path.isfile(self.invalid_domains_file_path)):
            with open(self.invalid_domains_file_path, "r") as f:
                return set(f.read().split("\n"))

        all_urls = set(itertools.chain(
            *[RuleItem(**rule_item, n_retries=5).url_list for rule_item in [
                *self.banning_rules_dicts,
                *self.direct_rules_dicts,
                *self.media_rules_dict,
                self.proxy_raw_list_dict
            ]]))
        return get_invalid_domains(
            all_urls, output_file=self.invalid_domains_file_path)

    def get_all_rule_set(self):
        invalid_domains = self.get_invalid_domains()

        banned_rule_set = RuleSets(
            rule_dicts=rulesets.BANNING_RULES,
            n_retries=self.n_retries)

        exist_rules = set(banned_rule_set.rule_set_copy)
        exist_rules_copy = set(banned_rule_set.rule_set_copy)

        banned_rule_set.write_all_rules(
            self.output_dir,
            exist_rules=exist_rules_copy,
            invalid_domains=invalid_domains)

        used_rules = exist_rules.difference(exist_rules_copy)

        direct_rule_set = RuleSets(
            rule_dicts=rulesets.DIRECT_RULES,
            n_retries=self.n_retries)

        exist_rules = set(direct_rule_set.rule_set_copy).difference(used_rules)
        exist_rules_copy = set(exist_rules)

        direct_rule_set.write_all_rules(
            self.output_dir,
            exist_rules=exist_rules_copy,
            invalid_domains=invalid_domains)

        used_rules = used_rules.union(exist_rules.difference(exist_rules_copy))

        proxy_rule_set = RuleSets(
            rule_dicts=rulesets.MEDIA_RULES,
            n_retries=self.n_retries)

        exist_rules = set(proxy_rule_set.rule_set_copy).difference(used_rules)
        exist_rules_copy = set(exist_rules)

        proxy_rule_set.write_all_rules(
            self.output_dir,
            exist_rules=exist_rules_copy,
            invalid_domains=invalid_domains)

        used_rules = used_rules.union(exist_rules.difference(exist_rules_copy))

        self.build_extra_proxy_list(
            proxy_rule_set, used_rules, invalid_domains)

    def build_extra_proxy_list(
            self, proxy_rule_set: RuleSets, exist_rules, invalid_domains):

        unused_domain_keywords = FORCE_DOMAIN_KEYWORDS.difference(
            proxy_rule_set.domain_keyword_set)
        domain_set_used = proxy_rule_set.domain_keyword_set.union(
            FORCE_DOMAIN_KEYWORDS)

        proxy_raw_dict = rulesets.PROXY_RAW_DICT
        proxy_raw_dict_domain_keywords = set(
            proxy_raw_dict.get("domain_keywords", [])).union(unused_domain_keywords)
        proxy_raw_dict["domain_keywords"] = proxy_raw_dict_domain_keywords

        proxy_ruleset_obj = RuleItem(
            n_retries=self.n_retries, **proxy_raw_dict
        )
        proxy_ruleset_obj.update_list(
            exist_rules=exist_rules,
            unused_domain_keywords=unused_domain_keywords,
            domain_keywords_readonly=domain_set_used,
            invalid_domains=invalid_domains
        )
        proxy_ruleset_obj.write_rules(self.output_dir)


if __name__ == "__main__":
    SurgeRules(
        output_dir="publish",
        banning_rules_dicts=rulesets.BANNING_RULES,
        direct_rules_dicts=rulesets.DIRECT_RULES,
        media_rules_dict=rulesets.MEDIA_RULES,
        proxy_raw_list_dict=rulesets.PROXY_RAW_DICT
    ).get_all_rule_set()
