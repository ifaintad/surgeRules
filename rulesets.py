import os

# rules

# banned rules
ADBLOCK = {
    "url": "https://raw.githubusercontent.com/NobyDa/Script/master/Surge/AdRule.list"}
HIJACKING = {
    "url": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/Hijacking/Hijacking.list"}
ADBLOCK3 = {
    "url": "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/BanAD.list"}
BAN_PROGRAM_AD = {
    "url": "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/BanProgramAD.list"}

SPOTIFY_AD = {
    "url": "https://raw.githubusercontent.com/Jigsaw88/Spotify-Ad-List/main/Spotify%20Adblock.txt",
    "file_name": "SpotifyAD.list",
    "has_prefix": False,
    "filter_top_level_banned_domain": False,
}


BANNING_RULES = [ADBLOCK, ADBLOCK3, HIJACKING, BAN_PROGRAM_AD, SPOTIFY_AD]

CHATGPT = {
    "url": "https://raw.githubusercontent.com/Toperlock/Quantumult/main/filter/OpenAI.list",  # noqa
    "domain_keywords": ["openaicom-api"],
}

SPECIAL_PROXY_RULES_BEFORE_DIRECT = [
    CHATGPT
]

# direct rules
APPLE = {
    "url": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/Apple/Apple.list"}
MICROSOFT = {
    "url": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/Microsoft/Microsoft.list"}
DIRECT_LAN = {
    "url": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/Lan/Lan.list"}
DIRECT_CN = {
    "url": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/China/China.list"}
DIRECT_IP = {
    "url": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/ChinaIPs/ChinaIPs.list"}
DIRECT_PRIVATE_TRACKER = {
    "url": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/PrivateTracker/PrivateTracker.list"}
SCHOLAR = {
    "url": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/Scholar/Scholar.list"}


DIRECT_RULES = [
    APPLE, MICROSOFT, DIRECT_LAN, DIRECT_CN, DIRECT_IP, DIRECT_PRIVATE_TRACKER, SCHOLAR
]

# media rules

YOUTUBE_MUSIC = {
    "url": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/YouTubeMusic/YouTubeMusic.list",
}

YOUTUBE = {
    "url": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/YouTube/YouTube.list",
    "domain_keywords": ["youtube", "youtubego"],
}
NETFLIX = {
    "url": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/Netflix/Netflix.list",
    "domain_keywords": ["netflix"],
}
DISNEY_PLUS = {
    "url": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/Disney/Disney.list",
    "domain_keywords": ["disney", "disneymagicmoments", "20thcenturystudios"],
}

SPOTIFY = {
    "url": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/Spotify/Spotify.list",
    "domain_keywords": ["-spotify-", "spotify.com"],
}

GOOGLE = {
    "url": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Google/Google.list",
    "domain_keywords": ["google", "googleapis", "blogspot"],
}

TELEGRAM = {
    "url": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/Telegram/Telegram.list",
    "domain_keywords": ["nicegram", "telegram"],
}

TWITTER = {
    "url": "https://raw.githubusercontent.com/ifaintad/ios_rule_script/master/rule/Surge/Twitter/Twitter.list",
    "domain_keywords": ["twitter"],
}

DOCKER = {
    "url": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Docker/Docker.list",
}


IP_RESTRICTED_RULES = [
    YOUTUBE_MUSIC, GOOGLE, YOUTUBE, NETFLIX, DISNEY_PLUS, SPOTIFY, TELEGRAM, TWITTER, DOCKER
]


# PAYPAL = "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/PayPal/PayPal.list"

# gfw list
PROXY_RAW_DICT = {
    "url": "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/gfw.txt",
    "file_name": "Proxy.list",
    "has_prefix": False,
    "filter_top_level_banned_domain": True,
}


DOMAIN_SUFFIX_ALWAYS_PROXY = {}
DOMAIN_SUFFIX_ALWAYS_BAN = {}
DOMAIN_SUFFIX_ALWAYS_DIRECT = {}
EXCLUDE_RULES = {}

extra_repo = os.getenv("EXTRA_GITHUB_REPO")
extra_repo_token = os.getenv("EXTRA_GITHUB_REPO_TOKEN")


if extra_repo and extra_repo_token:
    DOMAIN_SUFFIX_ALWAYS_PROXY = {
        "url": f"https://raw.githubusercontent.com/{extra_repo}/main/always_proxy",
        "file_name": "AlwaysProxy.list",
        "has_prefix": False,
        "filter_top_level_banned_domain": False,
        "token": extra_repo_token
    }

    DOMAIN_SUFFIX_ALWAYS_BAN = {
        "url": f"https://raw.githubusercontent.com/{extra_repo}/main/always_ban",
        "file_name": "AlwaysBan.list",
        "has_prefix": False,
        "filter_top_level_banned_domain": False,
        "token": extra_repo_token
    }

    DOMAIN_SUFFIX_ALWAYS_DIRECT = {
        "url": f"https://raw.githubusercontent.com/{extra_repo}/main/always_direct",
        "file_name": "AlwaysDirect.list",
        "has_prefix": False,
        "filter_top_level_banned_domain": False,
        "token": extra_repo_token
    }

    SING_BOX_PACKAGES_ALWAYS_DIRECT = {
        "url": f"https://raw.githubusercontent.com/{extra_repo}/main/always_direct_packages",
        "file_name": "AlwaysDirectPackages.list",
        "has_prefix": False,
        "filter_top_level_banned_domain": False,
        "token": extra_repo_token,
        "is_package": True
    }

    SING_BOX_PACKAGES_ALWAYS_PROXY = {
        "url": f"https://raw.githubusercontent.com/{extra_repo}/main/always_proxy_packages",
        "file_name": "AlwaysProxyPackages.list",
        "has_prefix": False,
        "filter_top_level_banned_domain": False,
        "token": extra_repo_token,
        "is_package": True
    }

    EXCLUDE_RULES = {
        "url": f"https://raw.githubusercontent.com/{extra_repo}/main/rules_exclude",
        "token": extra_repo_token
    }


CLOUDFLARE_IPV4 = "https://raw.githubusercontent.com/XIU2/CloudflareSpeedTest/master/ip.txt"
CLOUDFLARE_IPV6 = "https://raw.githubusercontent.com/XIU2/CloudflareSpeedTest/master/ipv6.txt"
