# ============================================================
#  企業 AI 工具可疑下載來源偵測器
#  適用環境：Google Colab / 本機 Python 3.8+
#  版本：1.0.0  |  2026-03-05
#
#  使用方式（Google Colab）：
#    1. 上傳此檔案至 Colab
#    2. 執行：!pip install requests beautifulsoup4 googlesearch-python colorama tabulate -q
#    3. 執行：%run ai_blacklist_detector.py
#
#  使用方式（本機）：
#    pip install requests beautifulsoup4 googlesearch-python colorama tabulate
#    python ai_blacklist_detector.py
# ============================================================

# ── 安裝相依套件（Colab 自動執行）──────────────────────────────
import subprocess, sys

def install(pkg):
    subprocess.check_call([sys.executable, "-m", "pip", "install", pkg, "-q"])

for pkg in ["requests", "beautifulsoup4", "googlesearch-python", "colorama", "tabulate"]:
    try:
        __import__(pkg.replace("-","_").split("-")[0])
    except ImportError:
        print(f"安裝 {pkg} 中...")
        install(pkg)

# ── 匯入套件 ────────────────────────────────────────────────────
import time
import re
import urllib.parse
from datetime import datetime

try:
    from tabulate import tabulate
    from colorama import Fore, Style, init
    init(autoreset=True)
    from googlesearch import search as google_search
    GOOGLE_AVAILABLE = True
except ImportError as e:
    print(f"[警告] 套件載入失敗：{e}，將使用靜態威脅情資模式")
    GOOGLE_AVAILABLE = False

# ── 搜尋關鍵字組合（模擬員工可能輸入的搜尋詞）──────────────────
SEARCH_QUERIES = [
    "ChatGPT 中文版 下載",
    "ChatGPT desktop 安裝 免費",
    "ChatGPT china download",
    "chatgpt unofficial download windows",
    "chatgpt破解版下載",
    "gpt4 免費桌面版",
    "ChatGPT bypass 下載",
    "whensunset chatgpt download",
    "chatgpt-china install",
]

# ── 官方白名單（排除用）────────────────────────────────────────
OFFICIAL_WHITELIST = [
    "openai.com",
    "chat.openai.com",
    "anthropic.com",
    "claude.ai",
    "microsoft.com",
    "copilot.microsoft.com",
    "gemini.google.com",
    "google.com",
    "bing.com",
    "yahoo.com",
    "github.com/openai",
    "apps.apple.com",
    "play.google.com",
    "wikipedia.org",
    "support.openai.com",
]

# ── 可疑關鍵字黑名單評分規則 ───────────────────────────────────
SUSPICIOUS_KEYWORDS = {
    # 中文可疑詞
    "中文版":       10,
    "破解":         25,
    "免費版":       10,
    "無限制":       20,
    "最新版":        8,
    "下載安裝":     12,
    "中國版":       30,
    "越牆":         35,
    "無需翻牆":     30,
    "不限流量":     20,
    "免費下載":     15,
    # 英文可疑詞
    "china":        20,
    "unofficial":   25,
    "bypass":       30,
    "free-download":20,
    "crack":        40,
    "pro-free":     35,
    "unlimited":    15,
    "no-vpn":       30,
    "desktop-free": 20,
    "chatgpt-go":   40,
    "openai-free":  35,
    "gpt-china":    45,
    "whensunset":   50,
    "chatgpt-china":50,
    # 檔名模式
    "setup.exe":    30,
    "installer.exe":25,
    ".gz":          20,
}

# ── 可疑域名正規表示式模式 ────────────────────────────────────
SUSPICIOUS_DOMAIN_PATTERNS = [
    (r"chat.?gpt(?!\.openai)",         "冒用chatgpt域名"),
    (r"openai(?!\.com)",               "冒用openai品牌"),
    (r"gpt.?(china|cn|free|pro)",      "GPT+中國/免費關鍵字"),
    (r"(free|crack|bypass).?gpt",      "破解/免費GPT"),
    (r"gpt.?(bypass|crack|unlimited)", "GPT繞過/破解"),
    (r"ai.?download",                  "AI下載站"),
    (r"chatbot.*(free|download)",      "免費聊天機器人下載"),
]

# ── 已知惡意域名資料庫（來自 Cyble / Malwarebytes / TrendMicro 威脅情資）
KNOWN_MALICIOUS_DOMAINS = {
    "chatgpt-go.online":            ("Lumma Stealer 散布站",          100),
    "chat-gpt-online-pc.com":       ("Aurora Stealer 下載點",         100),
    "chatgptfreeapp.com":           ("已知釣魚頁面",                   90),
    "chat.chatbotapp.ai":           ("非官方仿冒介面，資料收集站",      70),
    "openai-chatgpt.online":        ("仿冒 OpenAI 釣魚站",             85),
    "chatgpt4free.io":              ("免費誘餌釣魚站",                 80),
    "gpt4-download.com":            ("惡意安裝檔散布站",               95),
    "chatgpt-pro.download":         ("惡意 Pro 版誘餌",               90),
    "chatgpt-china.net":            ("中國版偽裝惡意軟體",             100),
    "whensunset.chatgpt-cn.com":    ("本次事件已確認惡意來源",         100),
    "ai-chatgpt-free.com":          ("仿冒 AI 工具下載站",             85),
    "gpt-unlimited.online":         ("無限制版誘餌站",                 80),
    "chatgpt-bypass.net":           ("VPN 繞過工具偽裝",               95),
    "free-chatgpt-download.com":    ("桌面版釣魚安裝程式",             88),
    "chatgpt-desktop-cn.com":       ("台灣定向攻擊站",                 92),
    "chatgpt-online.net":           ("仿冒 ChatGPT 線上版",            75),
    "gpt4online.com":               ("未授權 GPT-4 存取",              70),
    "chatgptx.download":            ("惡意下載站",                     90),
    "openai-gpt.download":          ("仿冒 OpenAI 下載頁",             88),
    "aichatbot-free.com":           ("免費 AI 誘餌站",                 72),
}

# ── 高風險 TLD 評分表 ─────────────────────────────────────────
RISKY_TLDS = {
    ".online":   15,
    ".xyz":      15,
    ".cn":       20,
    ".tk":       25,
    ".top":      10,
    ".club":     10,
    ".download": 30,
    ".icu":      20,
    ".site":     12,
    ".live":     12,
}

# ─────────────────────────────────────────────────────────────
#  核心評分函數
# ─────────────────────────────────────────────────────────────
def score_url(url: str, title: str = "", snippet: str = "") -> dict | None:
    """對 URL 進行多維度可疑度評分，回傳 None 表示白名單排除"""
    score = 0
    flags = []

    try:
        parsed = urllib.parse.urlparse(url)
        domain = parsed.netloc.lower().replace("www.", "")
        path   = parsed.path.lower()
        full   = (url + " " + title + " " + snippet).lower()
    except Exception:
        return None

    # 1. 官方白名單 → 排除
    for white in OFFICIAL_WHITELIST:
        if white in domain:
            return None

    # 2. 已知惡意域名（直接最高風險）
    for mal_domain, (reason, mal_score) in KNOWN_MALICIOUS_DOMAINS.items():
        if mal_domain in domain:
            score += mal_score
            flags.append(f"⛔ 已知惡意: {reason}")

    # 3. 可疑關鍵字評分
    for kw, pts in SUSPICIOUS_KEYWORDS.items():
        if kw in full:
            score += pts
            flags.append(f"🔑 可疑詞: '{kw}' (+{pts})")

    # 4. 域名模式比對
    for pattern, desc in SUSPICIOUS_DOMAIN_PATTERNS:
        if re.search(pattern, domain):
            score += 20
            flags.append(f"🌐 域名警示: {desc}")

    # 5. 高風險 TLD
    for tld, pts in RISKY_TLDS.items():
        if domain.endswith(tld):
            score += pts
            flags.append(f"🔴 高風險TLD: {tld} (+{pts})")

    # 6. 路徑中含可執行檔副檔名
    exe_exts = [".exe", ".msi", ".dmg", ".pkg", ".gz", ".zip", ".bat"]
    for ext in exe_exts:
        if ext in path:
            score += 25
            flags.append(f"📦 路徑含可執行檔: {ext}")

    # 7. 非 HTTPS
    if not url.startswith("https://"):
        score += 15
        flags.append("🔓 非 HTTPS 連線 (+15)")

    # 8. 數字堆疊域名
    if re.search(r"\d{6,}", domain):
        score += 20
        flags.append("🔢 域名含大量數字（垃圾站特徵）")

    # 風險等級
    if   score >= 80: risk = "🚨 極高風險"
    elif score >= 50: risk = "⚠️  高風險"
    elif score >= 25: risk = "🔶 中風險"
    else:             risk = "ℹ️  低風險"

    return {
        "url":    url,
        "domain": domain,
        "title":  (title[:60] if title else domain),
        "score":  score,
        "flags":  flags,
        "risk":   risk,
    }

# ─────────────────────────────────────────────────────────────
#  搜尋引擎爬取
# ─────────────────────────────────────────────────────────────
def collect_urls(queries: list, results_per_query: int = 8) -> list:
    collected = []

    if GOOGLE_AVAILABLE:
        print(f"\n{'='*60}")
        print(f"  🔍 開始搜尋引擎爬取（{len(queries)} 組查詢）")
        print(f"{'='*60}\n")
        for query in queries:
            print(f"  🔎 搜尋: {query}")
            try:
                urls = list(google_search(query, num_results=results_per_query, lang="zh-TW"))
                print(f"       → 取得 {len(urls)} 筆")
                for url in urls:
                    collected.append({"url": url, "query": query, "title": "", "snippet": ""})
                time.sleep(2)
            except Exception as e:
                print(f"       ⚠ 搜尋失敗: {e}")
    else:
        print("\n[靜態模式] 跳過即時搜尋，使用威脅情資資料庫")

    # 永遠補充已知惡意域名（威脅情資資料庫）
    print(f"\n  📋 載入威脅情資資料庫（{len(KNOWN_MALICIOUS_DOMAINS)} 筆已知惡意域名）")
    for domain in KNOWN_MALICIOUS_DOMAINS:
        collected.append({
            "url":     f"https://{domain}/download",
            "query":   "威脅情資資料庫",
            "title":   domain,
            "snippet": "",
        })

    return collected

# ─────────────────────────────────────────────────────────────
#  產生防火牆封鎖清單（多格式）
# ─────────────────────────────────────────────────────────────
def generate_blocklist(high_risk_results: list) -> str:
    lines = [
        "# ============================================================",
        f"# 企業 AI 工具可疑下載域名封鎖清單",
        f"# 產生時間: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"# 共 {len(high_risk_results)} 筆（風險分數 ≥ 50）",
        "# ============================================================",
        "",
        "# --- Squid Proxy 格式 ---",
    ]
    for r in high_risk_results:
        lines.append(f"acl blacklist_ai dstdomain .{r['domain']}  # score={r['score']}")
    lines += [
        "",
        "# --- iptables 格式 ---",
    ]
    for r in high_risk_results:
        lines.append(f"iptables -I FORWARD -d {r['domain']} -j DROP  # score={r['score']}")
    lines += [
        "",
        "# --- Windows hosts 檔格式 ---",
    ]
    for r in high_risk_results:
        lines.append(f"0.0.0.0  {r['domain']}  # score={r['score']}")
    lines += [
        "",
        "# --- Fortinet 格式 ---",
    ]
    for r in high_risk_results:
        lines.append(f"config firewall address")
        lines.append(f"    edit \"{r['domain']}\"")
        lines.append(f"        set type fqdn")
        lines.append(f"        set fqdn {r['domain']}")
        lines.append(f"    next")
        lines.append(f"end")
    return "\n".join(lines)

# ─────────────────────────────────────────────────────────────
#  主程式
# ─────────────────────────────────────────────────────────────
def run_detection():
    print("\n" + "="*65)
    print("  🛡️  企業 AI 工具可疑下載來源偵測器 v1.0")
    print(f"  執行時間: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*65)

    # Step 1: 收集 URL
    raw = collect_urls(SEARCH_QUERIES, results_per_query=6)

    # Step 2: 評分與去重
    print(f"\n  ⚙️  分析 {len(raw)} 筆 URL 中...\n")
    scored     = []
    seen_domains = set()

    for item in raw:
        result = score_url(item["url"], item.get("title",""), item.get("snippet",""))
        if result is None or result["score"] < 10:
            continue
        domain = result["domain"]
        if domain in seen_domains:
            continue
        seen_domains.add(domain)
        result["source_query"] = item.get("query","")
        scored.append(result)

    # Step 3: 取前 20
    top20 = sorted(scored, key=lambda x: x["score"], reverse=True)[:20]

    # Step 4: 輸出 TOP 20 表格
    print("="*80)
    print("  🚫 企業 AI 工具可疑下載黑名單 TOP 20")
    print("  （已排除官方來源：OpenAI / Anthropic / Microsoft / Google）")
    print("="*80 + "\n")

    table_data = []
    for i, r in enumerate(top20, 1):
        main_flag = r["flags"][0] if r["flags"] else "—"
        table_data.append([
            f"{i:02d}",
            r["domain"][:42],
            r["score"],
            r["risk"],
            main_flag[:48],
        ])

    print(tabulate(
        table_data,
        headers=["#", "Domain", "分數", "風險等級", "主要警示"],
        tablefmt="rounded_outline",
        colalign=("center","left","center","left","left"),
    ))

    # Step 5: 極高風險詳細分析
    print("\n" + "─"*80)
    print("  🔬 極高風險項目詳細分析（分數 ≥ 80）")
    print("─"*80)
    critical = [r for r in top20 if r["score"] >= 80]
    if critical:
        for r in critical:
            print(f"\n  🌐 {r['domain']}")
            print(f"     URL   : {r['url'][:72]}")
            print(f"     分數  : {r['score']}  |  等級: {r['risk']}")
            print(f"     來源  : {r['source_query']}")
            print(f"     警示  :")
            for flag in r["flags"][:5]:
                print(f"            {flag}")
    else:
        print("  本次掃描未發現極高風險站點")

    # Step 6: 輸出防火牆封鎖清單
    high_risk    = [r for r in top20 if r["score"] >= 50]
    blocklist_txt = generate_blocklist(high_risk)

    blocklist_file = "ai_suspicious_blocklist.txt"
    with open(blocklist_file, "w", encoding="utf-8") as f:
        f.write(blocklist_txt)
    print(f"\n  ✅ 防火牆封鎖清單已儲存至：{blocklist_file}")

    # Step 7: 統計摘要
    print("\n" + "="*65)
    print("  📊 掃描摘要")
    print("="*65)
    print(f"  總掃描 URL 數 : {len(raw)}")
    print(f"  去重後分析數  : {len(scored)}")
    print(f"  🚨 極高風險   : {sum(1 for r in top20 if r['score'] >= 80)} 筆（建議立即封鎖）")
    print(f"  ⚠️  高風險     : {sum(1 for r in top20 if 50 <= r['score'] < 80)} 筆（建議加入監控）")
    print(f"  🔶 中風險     : {sum(1 for r in top20 if 25 <= r['score'] < 50)} 筆（建議持續觀察）")
    print(f"\n  📋 建議行動：")
    print(f"     → 分數 ≥ 80：立即加入 Proxy/防火牆黑名單")
    print(f"     → 分數 ≥ 50：加入 SIEM 告警規則")
    print(f"     → 分數 ≥ 25：加入員工安全教育案例")
    print(f"\n  報告完成時間: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*65 + "\n")

    # Colab 下載（若在 Colab 環境）
    try:
        from google.colab import files
        files.download(blocklist_file)
        print(f"  ⬇️  封鎖清單已觸發下載：{blocklist_file}")
    except ImportError:
        print(f"  📁 非 Colab 環境，請直接開啟：{blocklist_file}")

# ─────────────────────────────────────────────────────────────
#  程式進入點
# ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    run_detection()
