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

# proxy roles
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
# PAYPAL = "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/PayPal/PayPal.list"

# gfw list
PROXY_RAW_LIST = {
    "url": "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/gfw.txt",
    "file_name": "Proxy.list",
    "has_prefix": False,
    "filter_top_level_banned_domain": True
}
