# 🛡️ 企業 AI 工具可疑下載來源偵測器

[![Open In Colab](https://colab.research.google.com/assets/colab-badge.svg)](https://colab.research.google.com/github/hpingsy/enterprise-ai-download-detector/blob/main/企業AI工具可疑下載偵測器.ipynb)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.8+](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/Platform-Google%20Colab-orange.svg)](https://colab.research.google.com/)

> 防止企業員工下載 `whensunset.chatgpt-china-9.5.3` 等惡意偽裝 AI 工具的自動化偵測與黑名單產生器。

---

## 📋 專案說明

隨著 AI 工具普及，攻擊者大量製造偽裝成 ChatGPT、Claude 等知名 AI 工具的惡意程式，
誘導使用者下載後竊取資料、植入木馬或回傳機密至境外伺服器。

本工具模擬員工搜尋 AI 工具的行為，自動偵測並評分可疑下載來源，
產生可直接套用於企業防火牆的封鎖清單。

### 🎯 設計靈感

延伸自「偵測假 LINE 模仿使用者上網搜尋」的防護邏輯：

```
假 LINE 路徑：搜尋 "LINE下載"  → 點擊假網站 → 下載 LineInstaller.exe
假 AI 路徑：  搜尋 "ChatGPT"   → 點擊假網站 → 下載 chatgpt-china-9.5.3
```

---

## ✨ 功能特色

| 功能 | 說明 |
|------|------|
| 🔍 **搜尋引擎爬取** | 模擬 9 組員工常用搜尋詞，即時取得搜尋結果 |
| ⚖️ **多維度評分** | 關鍵字、域名模式、TLD、執行檔路徑、HTTPS 共 8 個維度 |
| 🗄️ **威脅情資資料庫** | 內建 20 筆已知惡意域名（Cyble / Malwarebytes / TrendMicro） |
| 🚫 **白名單排除** | 自動排除 OpenAI、Anthropic、Microsoft、Google 等官方來源 |
| 📋 **多格式封鎖清單** | 自動產生 Squid Proxy、iptables、Windows hosts、Fortinet 四種格式 |
| ⬇️ **一鍵下載** | 在 Colab 中自動觸發封鎖清單下載 |

---

## 🚀 快速開始

### 方式一：Google Colab（推薦，無需安裝）

點擊上方 **「Open in Colab」** 按鈕，接著點選：

```
執行階段 → 全部執行（Ctrl+F9）
```

### 方式二：本機執行

```bash
# 1. 複製專案
git clone https://github.com/hpingsy/enterprise-ai-download-detector.git
cd enterprise-ai-download-detector

# 2. 安裝套件
pip install -r requirements.txt

# 3. 執行偵測
python ai_blacklist_detector.py
```

---

## 📊 輸出範例

```
╭────┬──────────────────────────────────────┬──────┬───────────┬──────────────────────────────╮
│ #  │ Domain                               │ 分數 │ 風險等級  │ 主要警示                     │
├────┼──────────────────────────────────────┼──────┼───────────┼──────────────────────────────┤
│ 01 │ chatgpt-go.online                    │ 155  │ 🚨 極高   │ ⛔ 已知惡意: Lumma Stealer   │
│ 02 │ whensunset.chatgpt-cn.com            │ 150  │ 🚨 極高   │ ⛔ 已知惡意: 本次事件來源    │
│ 03 │ chatgpt-china.net                    │ 150  │ 🚨 極高   │ ⛔ 已知惡意: 中國版偽裝惡意  │
│ 04 │ gpt4-download.com                    │ 120  │ 🚨 極高   │ ⛔ 已知惡意: 惡意安裝檔散布  │
│ 05 │ chatgpt-bypass.net                   │ 125  │ 🚨 極高   │ ⛔ 已知惡意: VPN繞過工具偽裝 │
╰────┴──────────────────────────────────────┴──────┴───────────┴──────────────────────────────╯
```

產生的封鎖清單 `ai_suspicious_blocklist.txt` 包含四種格式：

```bash
# Squid Proxy
acl blacklist_ai dstdomain .chatgpt-go.online

# iptables
iptables -I FORWARD -d chatgpt-go.online -j DROP

# Windows hosts
0.0.0.0  chatgpt-go.online

# Fortinet
config firewall address
    edit "chatgpt-go.online"
        set type fqdn
        set fqdn chatgpt-go.online
    next
end
```

---

## 📁 檔案結構

```
enterprise-ai-download-detector/
├── 企業AI工具可疑下載偵測器.ipynb   # Google Colab Notebook（主程式）
├── ai_blacklist_detector.py          # 本機執行版 Python 腳本
├── requirements.txt                  # 相依套件清單
├── LICENSE                           # MIT 授權
└── README.md                         # 本說明文件
```

---

## ⚙️ 評分規則說明

| 評分維度 | 範例 | 分數 |
|---------|------|------|
| 已知惡意域名 | `chatgpt-go.online` | +100 |
| 高危關鍵字 | `chatgpt-china`、`bypass` | +20~50 |
| 可疑域名模式 | `chat*gpt` 非官方 | +20 |
| 高風險 TLD | `.download`、`.cn`、`.online` | +10~30 |
| 含執行檔路徑 | `.exe`、`.msi`、`.gz` | +25 |
| 非 HTTPS | `http://` 連線 | +15 |

**風險等級判定：**
- 🚨 極高風險：≥ 80 分 → 建議立即加入防火牆黑名單
- ⚠️  高風險：50–79 分 → 建議加入 SIEM 告警規則
- 🔶 中風險：25–49 分 → 建議加入員工安全教育案例

---

## 🔄 威脅情資來源

- [Cyble Research](https://cyble.com/blog/) — ChatGPT 釣魚站點分析
- [Malwarebytes](https://www.malwarebytes.com/blog/) — 假 AI 工具惡意程式報告
- [Trend Micro](https://www.trendmicro.com/) — 假 LINE / 假 AI 台灣攻擊案例
- [TaiwanNews](https://www.taiwannews.com.tw/) — 台灣在地威脅情資

---

## ⚠️ 免責聲明

本工具僅供**資安教育與企業防護研究**使用。
域名評分結果為統計模型輸出，不代表最終法律判定。
建議搭配專業資安團隊人工複核後再部署封鎖規則。

---

## 📄 授權

本專案採用 [MIT License](LICENSE) 授權開放原始碼。

---

## 🤝 貢獻

歡迎提交 Issue 或 Pull Request，協助更新威脅情資資料庫！

1. Fork 此專案
2. 建立功能分支：`git checkout -b feature/add-new-ioc`
3. 提交變更：`git commit -m 'feat: 新增最新 IOC 資料'`
4. 推送分支：`git push origin feature/add-new-ioc`
5. 開啟 Pull Request
