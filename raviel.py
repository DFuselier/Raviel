import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog, simpledialog
import threading
import queue
import os
import sys
import ssl
import json
import csv
import socket
import urllib.request
import urllib.error
import urllib.parse
import email.utils
import gzip
import re
import time
import concurrent.futures
from datetime import datetime, timedelta, timezone


# ---------------------------------------------------------------------------
# CONFIGURATION LOADER
# ---------------------------------------------------------------------------

CONFIG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")
HEALTH_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "feed_health.json")

_DEFAULTS = {
    "your_email":          "anonymous@example.com",
    "source_file":         "valid_sources.txt",
    "timeout_seconds":     20,
    "max_workers":         10,
    "dead_feed_threshold": 3,
    "high_priority_terms": [

    ],
    "tld_map": {
        ".fr": "France", ".in": "India", ".uk": "United Kingdom", ".jp": "Japan",
        ".cn": "China", ".ru": "Russia", ".de": "Germany", ".au": "Australia",
        ".ca": "Canada", ".br": "Brazil", ".sg": "Singapore", ".hk": "Hong Kong",
        ".it": "Italy", ".es": "Spain", ".nl": "Netherlands", ".ch": "Switzerland",
        ".gov": "USA", ".mil": "USA"
    }
}

def load_config():
    """Load settings from config.json, falling back to built-in defaults for any missing key."""
    cfg = dict(_DEFAULTS)
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                data = json.load(f)
            for key in _DEFAULTS:
                if key in data:
                    cfg[key] = data[key]
        except (json.JSONDecodeError, OSError) as e:
            print(f"[WARNING] Could not read config.json ({e}). Using built-in defaults.")
    else:
        print(f"[WARNING] config.json not found at '{CONFIG_FILE}'. Using built-in defaults.")
    return cfg

CFG = load_config()

SOURCE_FILE         = CFG["source_file"]
TIMEOUT_SECONDS     = CFG["timeout_seconds"]
MAX_WORKERS         = CFG["max_workers"]
YOUR_EMAIL          = CFG["your_email"]
HIGH_PRIORITY_TERMS = CFG["high_priority_terms"]
TLD_MAP             = CFG["tld_map"]
DEAD_FEED_THRESHOLD = int(CFG["dead_feed_threshold"])

SEC_USER_AGENT = f"Mozilla/5.0 (compatible; OSINT-Scanner/1.0; +{YOUR_EMAIL})"


# ---------------------------------------------------------------------------
# IOC REGEX PATTERNS
# ---------------------------------------------------------------------------

IOC_REGEX = {
    'ipv4': re.compile(
        r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
        r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    ),
    'email':            re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'),
    'md5':              re.compile(r'\b[a-fA-F0-9]{32}\b'),
    'sha1':             re.compile(r'\b[a-fA-F0-9]{40}\b'),
    'sha256':           re.compile(r'\b[a-fA-F0-9]{64}\b'),
    'cve':              re.compile(r'CVE-\d{4}-\d{4,}', re.IGNORECASE),
    'suspicious_files': re.compile(r'\.(exe|dll|bat|sh|ps1|apk|jar|elf)\b', re.IGNORECASE),
}

IOC_CONTEXT_WORDS = re.compile(
    r'\b(malware|hash|ioc|indicator|sha|md5|trojan|ransomware|exploit|'
    r'payload|backdoor|c2|command.and.control|threat|sample|dropper)\b',
    re.IGNORECASE
)

STANDARD_HEADERS = {
    'User-Agent': (
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
        '(KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36'
    ),
    'Accept':          'application/rss+xml, application/xml, application/atom+xml, text/xml, text/html, */*',
    'Accept-Language': 'en-US,en;q=0.9',
    'Cache-Control':   'no-cache',
    'Connection':      'keep-alive',
}


# ---------------------------------------------------------------------------
# DEPENDENCY CHECK
# ---------------------------------------------------------------------------

try:
    import feedparser
except ImportError:
    print("CRITICAL: 'feedparser' is missing. Please run: pip install feedparser")
    sys.exit(1)

socket.setdefaulttimeout(TIMEOUT_SECONDS)


# ---------------------------------------------------------------------------
# FEED HEALTH DATABASE
# ---------------------------------------------------------------------------

def _now_str():
    """Return the current UTC time as a readable string."""
    return datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')


# Staleness thresholds: (max_days_or_None, label, tag_name, hex_colour)
# visible without needing per-cell background colours (Treeview does not support
# per-cell colouring natively).
_STALENESS_BANDS = [
    (30,   'Fresh',   'stale_fresh',   '#d4edda'),  # < 30 days
    (90,   'Aging',   'stale_aging',   '#fff3cd'),  # 30-90 days
    (180,  'Stale',   'stale_stale',   '#fde8cc'),  # 90-180 days
    (365,  'Old',     'stale_old',     '#f8d7da'),  # 180-365 days
    (None, 'Dormant', 'stale_dormant', '#e2e3e5'),  # 365+ days
]


class FeedHealthDB:
    """Tracks per-feed health statistics and persists them to feed_health.json."""

    STATUS_COLOURS = {
        'Good':     '#d4edda',
        'Unstable': '#fff3cd',
        'Poor':     '#f8d7da',
        'Dead':     '#e2e3e5',
        'New':      '#cce5ff',
        'Unknown':  '#ffffff',
    }

    def __init__(self, path):
        self.path = path
        self.data = self._load()

    # --- Persistence ---

    def _load(self):
        if os.path.exists(self.path):
            try:
                with open(self.path, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except (json.JSONDecodeError, OSError) as e:
                print(f"[WARNING] Could not load feed_health.json ({e}). Starting fresh.")
        return {}

    def save(self):
        """Write the current in-memory data to feed_health.json."""
        try:
            with open(self.path, 'w', encoding='utf-8') as f:
                json.dump(self.data, f, indent=2, ensure_ascii=False)
        except OSError as e:
            print(f"[WARNING] Could not save feed_health.json: {e}")

    # --- Recording scan outcomes ---

    def record_success(self, url, category, article_count, newest_article_date=None):
        """Record a successful fetch.

        Args:
            url:                  Feed URL.
            category:             Category from valid_sources.txt.
            article_count:        Articles found inside the scan time window.
            newest_article_date:  ISO date string (YYYY-MM-DD) of the most
                                  recently published article in the entire feed,
                                  regardless of the scan window.  Used for
                                  staleness tracking.
        """
        entry = self._get_or_create(url, category)
        entry['category']             = category
        entry['total_scans']         += 1
        entry['total_successes']     += 1
        entry['total_articles']      += article_count
        entry['consecutive_failures'] = 0
        entry['last_success']         = _now_str()

        # Only update if we have a newer date.
        if newest_article_date:
            existing = entry.get('last_article_date')
            if not existing or newest_article_date > existing:
                entry['last_article_date'] = newest_article_date

        self.data[url] = entry

    def record_failure(self, url, category, error_msg):
        """Record a failed fetch for a URL."""
        entry = self._get_or_create(url, category)
        entry['category']             = category
        entry['total_scans']         += 1
        entry['consecutive_failures'] += 1
        entry['last_error']           = _now_str()
        entry['last_error_msg']       = str(error_msg)[:300]
        self.data[url] = entry

    # --- Querying: health status ---

    def get_dead_feeds(self, threshold):
        """Return {url: entry} for feeds at or above the failure threshold."""
        return {
            url: entry for url, entry in self.data.items()
            if entry.get('consecutive_failures', 0) >= threshold
        }

    def get_status(self, url):
        """Return a human-readable health status label for a URL."""
        if url not in self.data:
            return 'Unknown'
        entry = self.data[url]
        cf    = entry.get('consecutive_failures', 0)
        total = entry.get('total_scans', 0)
        if cf >= DEAD_FEED_THRESHOLD:
            return 'Dead'
        if cf > 0:
            return 'Unstable'
        if total == 0:
            return 'New'
        rate = entry.get('total_successes', 0) / total
        if rate >= 0.8:
            return 'Good'
        return 'Poor'

    def get_success_rate_str(self, url):
        """Return a 'successes/total' display string, e.g. '9/10'."""
        if url not in self.data:
            return '—'
        e = self.data[url]
        return f"{e.get('total_successes', 0)}/{e.get('total_scans', 0)}"

    def get_avg_articles_str(self, url):
        """Return average articles per successful scan as a string."""
        if url not in self.data:
            return '—'
        e = self.data[url]
        s = e.get('total_successes', 0)
        if s == 0:
            return '0'
        return str(round(e.get('total_articles', 0) / s, 1))

    # --- Querying: staleness ---

    def get_staleness_info(self, url):
        """Return (label, tag_name, hex_colour) for this feed's last_article_date.

        Staleness bands:
          Fresh   < 30 days
          Aging   30-90 days
          Stale   90-180 days
          Old     180-365 days
          Dormant 365+ days
          Unknown no date recorded yet
        """
        if url not in self.data:
            return ('Unknown', 'stale_unknown', '#ffffff')

        date_str = self.data[url].get('last_article_date')
        if not date_str:
            return ('Unknown', 'stale_unknown', '#ffffff')

        try:
            last_dt = datetime.fromisoformat(date_str)
            if last_dt.tzinfo is None:
                last_dt = last_dt.replace(tzinfo=timezone.utc)
        except ValueError:
            return ('Unknown', 'stale_unknown', '#ffffff')

        age_days = (datetime.now(timezone.utc) - last_dt).days

        for threshold, label, tag, colour in _STALENESS_BANDS:
            if threshold is None or age_days < threshold:
                return (label, tag, colour)

        return ('Dormant', 'stale_dormant', '#e2e3e5')

    def get_staleness_col_str(self, url):
        """Return the formatted string for the 'Last Published' column.

        Format: 'LABEL YYYY-MM-DD'  or  'Never seen'
        """
        if url not in self.data:
            return 'Never seen'
        date_str = self.data[url].get('last_article_date')
        if not date_str:
            return 'Never seen'
        label, _, _ = self.get_staleness_info(url)
        return f"{label} {date_str[:10]}"

    # --- Querying: notes ---

    def get_note(self, url):
        """Return the user annotation for a feed, or empty string if none."""
        if url not in self.data:
            return ''
        return self.data[url].get('note', '')

    def set_note(self, url, text):
        """Set the user annotation for a feed.  Call save() afterwards to persist."""
        if url in self.data:
            self.data[url]['note'] = str(text).strip()

    # --- Category aggregation ---

    def get_category_summary(self):
        """Return a list of per-category aggregate dicts sorted by category name.

        Each dict keys: category, total_feeds, good, unstable, poor, dead,
        new_feeds, avg_success_rate, freshest_date, stalest_date.
        """
        cats = {}
        for url, entry in self.data.items():
            cat    = entry.get('category', 'Uncategorized')
            status = self.get_status(url)
            if cat not in cats:
                cats[cat] = {
                    'category':       cat,
                    'total_feeds':    0,
                    'good':           0,
                    'unstable':       0,
                    'poor':           0,
                    'dead':           0,
                    'new_feeds':      0,
                    '_success_rates': [],
                    '_article_dates': [],
                }
            c = cats[cat]
            c['total_feeds'] += 1
            key_map = {'good': 'good', 'unstable': 'unstable', 'poor': 'poor',
                       'dead': 'dead', 'new': 'new_feeds'}
            sk = status.lower()
            if sk in key_map:
                c[key_map[sk]] += 1

            total = entry.get('total_scans', 0)
            if total > 0:
                c['_success_rates'].append(entry.get('total_successes', 0) / total)

            d = entry.get('last_article_date')
            if d:
                c['_article_dates'].append(d)

        result = []
        for c in cats.values():
            rates = c.pop('_success_rates')
            dates = c.pop('_article_dates')
            c['avg_success_rate'] = (
                f"{round(sum(rates) / len(rates) * 100)}%" if rates else '—'
            )
            c['freshest_date'] = max(dates)[:10] if dates else '—'
            c['stalest_date']  = min(dates)[:10] if dates else '—'
            result.append(c)

        return sorted(result, key=lambda x: x['category'].lower())

    # --- Misc ---

    def remove_urls(self, urls_to_remove):
        """Delete entries for the given URLs from the in-memory DB."""
        for url in urls_to_remove:
            self.data.pop(url, None)

    # --- Internal ---

    def _get_or_create(self, url, category):
        if url not in self.data:
            self.data[url] = {
                'category':             category,
                'consecutive_failures': 0,
                'total_scans':          0,
                'total_successes':      0,
                'total_articles':       0,
                'last_article_date':    None,   # ISO date of newest article ever seen
                'last_success':         None,
                'last_error':           None,
                'last_error_msg':       None,
                'note':                 '',     # free-text user annotation
                'first_seen':           _now_str(),
            }
        return self.data[url]


# ---------------------------------------------------------------------------
# HELPER FUNCTIONS
# ---------------------------------------------------------------------------

def get_cutoff_time():
    """Return (cutoff_datetime, mode_label) based on the current day of week."""
    now = datetime.now(timezone.utc)
    if now.weekday() == 0:
        return now - timedelta(hours=72), "Weekend Mode (72h)"
    return now - timedelta(hours=24), "Daily Mode (24h)"


def get_country_from_url(url):
    """Guess a country name from the TLD of a URL."""
    try:
        domain = urllib.parse.urlparse(url).netloc
        for tld, country in TLD_MAP.items():
            if domain.endswith(tld):
                return country
        if '.gov.' in domain:
            return TLD_MAP.get('.' + domain.split('.')[-1], "Unknown")
        return "Global / Unknown"
    except (ValueError, AttributeError):
        return "Unknown"


def parse_date_smart(date_obj_or_str):
    """Parse a date from various formats into a timezone-aware datetime object.

    Accepts feedparser time tuples, email-format strings, and a wide range of
    ISO / RFC / locale date strings.  Returns None if the input cannot be parsed.
    """
    if not date_obj_or_str:
        return None

    # feedparser often gives us a time.struct_time / 9-tuple
    if isinstance(date_obj_or_str, tuple):
        try:
            # Guard against zero-valued or out-of-range struct fields
            year = date_obj_or_str[0]
            if year and year > 1970:
                return datetime(*date_obj_or_str[:6], tzinfo=timezone.utc)
        except (ValueError, TypeError):
            pass

    date_str = str(date_obj_or_str).strip()

    # Strip common timezone name suffixes that strptime %Z can't always handle
    date_str_clean = re.sub(r'\s+(GMT|UTC|EST|PST|EDT|PDT|CST|CDT|MST|MDT)$', '', date_str)

    try:
        parsed = email.utils.parsedate_to_datetime(date_str)
        if parsed:
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        pass

    manual_formats = [
        # RFC / email variants
        '%d %b, %Y %z',
        '%d %b %Y %H:%M:%S %z',
        '%a, %d %b %Y %H:%M:%S %Z',
        '%a %b %d %H:%M:%S %Z %Y',        # Unix ctime: "Thu Mar  6 12:00:00 UTC 2026"
        # ISO 8601 variants
        '%Y-%m-%dT%H:%M:%S%z',
        '%Y-%m-%dT%H:%M:%SZ',
        '%Y-%m-%dT%H:%M:%S.%f%z',          # microseconds with offset
        '%Y-%m-%dT%H:%M:%S.%fZ',           # microseconds, Z suffix
        '%Y-%m-%dT%H:%M:%S',               # no timezone
        '%Y-%m-%d %H:%M:%S',
        '%Y-%m-%d %H:%M:%S%z',
        '%Y-%m-%d',                         # date-only (NIST, some gov feeds)
        # Locale-style
        '%d %B %Y',                         # "06 March 2026"
        '%B %d, %Y',                        # "March 06, 2026"
        '%d-%b-%Y',                         # "06-Mar-2026"
        # Asian feed formats
        '%Y/%m/%d %H:%M:%S',
        '%Y/%m/%d',
    ]

    for fmt in manual_formats:
        for s in (date_str, date_str_clean):
            try:
                dt = datetime.strptime(s, fmt)
                return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
            except ValueError:
                continue

    return None


def strip_html(text):
    """Remove HTML tags from a string, replacing each tag with a space."""
    if not text:
        return ""
    return re.sub(r'<[^>]+>', ' ', text)


def check_for_iocs(text):
    """Scan text for Indicators of Compromise (IOCs)."""
    if not text:
        return False
    for key in ('ipv4', 'email', 'cve', 'suspicious_files'):
        if IOC_REGEX[key].search(text):
            return True
    if IOC_CONTEXT_WORDS.search(text):
        for key in ('md5', 'sha1', 'sha256'):
            if IOC_REGEX[key].search(text):
                return True
    return False


def _build_ssl_context(verify=True):
    """Return an SSL context.  When verify=False, disables cert checking."""
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
    return ctx


def fetch_feed_content(url):
    """Fetch raw feed bytes from a URL.

    Resilience strategy (in order):
      1. Normal request with full SSL verification.
      2. On SSL certificate error  → retry once with verification disabled.
      3. On HTTP 429              → retry up to 2x with exponential back-off (1s, 2s).
      4. On HTTP 521/522/524      → retry once after 1 s (Cloudflare transient errors).
      5. On socket timeout         → retry once immediately.
      6. HTTP 403                 → return b"ERROR: 403 Forbidden" (not an exception).
      7. Any other error          → raise so the caller records a failure.
    """
    headers = {'User-Agent': SEC_USER_AGENT} if "sec.gov" in url else STANDARD_HEADERS

    def _do_request(verify_ssl=True, attempt=0):
        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(
                req,
                timeout=TIMEOUT_SECONDS,
                context=_build_ssl_context(verify_ssl),
            ) as response:
                content = response.read()

                if response.info().get('Content-Encoding') == 'gzip':
                    try:
                        content = gzip.decompress(content)
                    except gzip.BadGzipFile:
                        pass
                    except OSError as e:
                        raise RuntimeError(f"Gzip decompression failed: {e}") from e

                try:
                    return content.decode('utf-8-sig').strip().encode('utf-8')
                except UnicodeDecodeError:
                    return content.decode('iso-8859-1').encode('utf-8')

        except urllib.error.HTTPError as e:
            if e.code == 403:
                return b"ERROR: 403 Forbidden"

            # Rate-limited: back off and retry up to twice
            if e.code == 429 and attempt < 2:
                time.sleep(2 ** attempt)        # 1 s, then 2 s
                return _do_request(verify_ssl=verify_ssl, attempt=attempt + 1)

            # Cloudflare origin-unreachable: one quick retry
            if e.code in (521, 522, 524) and attempt == 0:
                time.sleep(1)
                return _do_request(verify_ssl=verify_ssl, attempt=1)

            raise

        except urllib.error.URLError as e:
            reason = str(getattr(e, 'reason', e))

            # SSL certificate problem: retry without verification
            if verify_ssl and ('CERTIFICATE_VERIFY_FAILED' in reason or
                               'certificate verify failed' in reason or
                               'SSL' in reason):
                return _do_request(verify_ssl=False, attempt=attempt)

            raise

        except (TimeoutError, socket.timeout, OSError):
            # One retry on transient socket/timeout failures
            if attempt == 0:
                return _do_request(verify_ssl=verify_ssl, attempt=1)
            raise

    return _do_request()


def process_single_feed(source_data, cutoff):
    """Fetch and parse one RSS/Atom feed.

    Returns (category, findings_or_None, error_or_None).

    findings includes 'newest_article_date' — the ISO date of the most recently
    published entry across the ENTIRE feed (not just within the cutoff window).
    This allows staleness tracking even on scans where no articles are new.
    """
    category, url = source_data

    try:
        raw_xml = fetch_feed_content(url)

        if raw_xml.startswith(b"ERROR:"):
            return (category, None, {'url': url, 'category': category, 'error': raw_xml.decode()})

        feed = feedparser.parse(raw_xml)
        if feed.bozo and not feed.entries:
            return (category, None, {'url': url, 'category': category, 'error': "Invalid Feed Data"})

        site_title      = feed.feed.get('title', url[:30] + "...")
        site_buffer     = []
        newest_pub_date = None   # tracks newest date across ALL entries in feed

        for entry in feed.entries:
            pub_date = None

            # feedparser parsed fields (time tuples) — try first
            for attr in ('published_parsed', 'updated_parsed', 'created_parsed'):
                val = getattr(entry, attr, None)
                if val:
                    pub_date = parse_date_smart(val)
                    if pub_date:
                        break

            # Raw string fields — feedparser may expose date as string even when
            # it can't fully parse the tuple (common in non-English / gov feeds)
            if not pub_date:
                for cand in [
                    entry.get('published'),
                    entry.get('updated'),
                    entry.get('pubDate'),
                    entry.get('date'),
                    entry.get('created'),
                    entry.get('dc_date'),           # Dublin Core date
                    entry.get('dcterms_modified'),  # Dublin Core modified
                ]:
                    if cand and isinstance(cand, str):
                        pub_date = parse_date_smart(cand)
                        if pub_date:
                            break

            # Update newest across the whole feed regardless of cutoff
            if pub_date:
                if newest_pub_date is None or pub_date > newest_pub_date:
                    newest_pub_date = pub_date

            # Only collect articles within the scan window for the report
            if pub_date and pub_date > cutoff:
                title       = entry.get('title', 'No Title')
                link        = entry.get('link', url)
                raw_summary = entry.get('summary', entry.get('description', ''))
                scan_text   = f"{title} {link} {strip_html(raw_summary)}"

                site_buffer.append({
                    'title':          title,
                    'link':           link,
                    'date':           pub_date.strftime('%Y-%m-%d %H:%M'),
                    'priority_terms': [t for t in HIGH_PRIORITY_TERMS if t.lower() in scan_text.lower()],
                    'has_ioc':        check_for_iocs(scan_text),
                })

        newest_article_date = newest_pub_date.strftime('%Y-%m-%d') if newest_pub_date else None

        findings = {
            'site_title':          site_title,
            'url':                 url,
            'country':             get_country_from_url(url),
            'articles':            site_buffer,
            'article_count':       len(site_buffer),
            'newest_article_date': newest_article_date,
        }

    except Exception as e:
        return (category, None, {'url': url, 'category': category, 'error': str(e)})

    return (category, findings, None)


# ---------------------------------------------------------------------------
# GUI APPLICATION CLASS
# ---------------------------------------------------------------------------

class OSINTApp:
    def __init__(self, root):
        self.root = root
        self.root.title("OSINT Threat Scanner")
        self.root.geometry("1000x800")

        self.style = ttk.Style()
        self.style.theme_use('clam')

        self.category_indices = {}
        self.health_db        = FeedHealthDB(HEALTH_FILE)

        self.setup_menu()
        self.setup_ui()
        self.setup_context_menu()

        self.queue = queue.Queue()
        self.root.after(100, self.process_queue)

    # ------------------------------------------------------------------
    # UI SETUP
    # ------------------------------------------------------------------

    def setup_menu(self):
        menubar = tk.Menu(self.root)

        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Save Output As...", command=self.save_as_file)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        menubar.add_cascade(label="File", menu=file_menu)

        edit_menu = tk.Menu(menubar, tearoff=0)
        edit_menu.add_command(label="Copy All Text", command=self.copy_all)
        edit_menu.add_command(label="Search...",     command=self.open_search)
        menubar.add_cascade(label="Edit", menu=edit_menu)

        tools_menu = tk.Menu(menubar, tearoff=0)
        tools_menu.add_command(label="Feed Health Dashboard", command=self.open_feed_health_window)
        tools_menu.add_command(label="Dead Feed Manager",     command=self.open_dead_feed_manager)
        menubar.add_cascade(label="Tools", menu=tools_menu)

        self.root.config(menu=menubar)

    def setup_ui(self):
        control_frame = ttk.Frame(self.root, padding="10")
        control_frame.pack(fill=tk.X)

        self.btn_scan   = ttk.Button(control_frame, text="START SCAN",   command=self.start_scan_thread)
        self.btn_scan.pack(side=tk.LEFT, padx=5)

        self.btn_edit   = ttk.Button(control_frame, text="EDIT SOURCES", command=self.open_source_editor)
        self.btn_edit.pack(side=tk.LEFT, padx=5)

        self.btn_health = ttk.Button(control_frame, text="FEED HEALTH",  command=self.open_feed_health_window)
        self.btn_health.pack(side=tk.LEFT, padx=5)

        self.lbl_status = ttk.Label(control_frame, text="Ready", font=("Arial", 10, "bold"))
        self.lbl_status.pack(side=tk.LEFT, padx=15)

        ttk.Label(control_frame, text="Jump to section:").pack(side=tk.LEFT, padx=(20, 5))
        self.nav_var   = tk.StringVar()
        self.nav_combo = ttk.Combobox(control_frame, textvariable=self.nav_var, state='readonly', width=25)
        self.nav_combo.pack(side=tk.LEFT)
        self.nav_combo.bind("<<ComboboxSelected>>", self.jump_to_category)

        self.progress = ttk.Progressbar(self.root, orient=tk.HORIZONTAL, mode='determinate')
        self.progress.pack(fill=tk.X, padx=10, pady=5)

        self.log_area = scrolledtext.ScrolledText(self.root, state='disabled', height=40, font=("Consolas", 10))
        self.log_area.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.log_area.tag_config("INFO",    foreground="black")
        self.log_area.tag_config("ERROR",   foreground="red")
        self.log_area.tag_config("SUCCESS", foreground="green")
        self.log_area.tag_config("ALERT",   foreground="red", font=("Consolas", 11, "bold"))
        self.log_area.tag_config("HEADER",  background="#eeeeee", font=("Consolas", 11, "bold"))

    def setup_context_menu(self):
        """Create the right-click copy context menu for the log area."""
        self.context_menu = tk.Menu(self.root, tearoff=0)
        self.context_menu.add_command(label="Copy", command=self.copy_selection)
        self.log_area.bind("<Button-3>", self.show_context_menu)

    # ------------------------------------------------------------------
    # FEED HEALTH DASHBOARD  (tabbed: By Feed | By Category)
    # ------------------------------------------------------------------

    def open_feed_health_window(self):
        """Open the Feed Health Dashboard with By-Feed and By-Category tabs."""
        win = tk.Toplevel(self.root)
        win.title("Feed Health Dashboard")
        win.geometry("1200x650")
        win.resizable(True, True)

        # --- Summary bar ---
        counts = {}
        for url in self.health_db.data:
            s = self.health_db.get_status(url)
            counts[s] = counts.get(s, 0) + 1

        summary_frame = ttk.Frame(win, padding="10 8 10 4")
        summary_frame.pack(fill=tk.X)

        ttk.Label(
            summary_frame,
            text=(
                f"  {len(self.health_db.data)} feeds tracked"
                f"  |  {counts.get('Good', 0)} Good"
                f"  {counts.get('Unstable', 0)} Unstable"
                f"  {counts.get('Poor', 0)} Poor"
                f"  {counts.get('Dead', 0)} Dead"
                f"  {counts.get('New', 0)} New"
            ),
            font=("Arial", 10),
        ).pack(side=tk.LEFT)

        ttk.Button(summary_frame, text="Manage Dead Feeds",
                   command=self.open_dead_feed_manager).pack(side=tk.RIGHT, padx=5)

        ttk.Separator(win, orient='horizontal').pack(fill=tk.X, padx=10)

        # --- Notebook ---
        notebook = ttk.Notebook(win)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=6)

        feed_tab = ttk.Frame(notebook)
        cat_tab  = ttk.Frame(notebook)
        notebook.add(feed_tab, text="  By Feed  ")
        notebook.add(cat_tab,  text="  By Category  ")

        feed_tree = self._build_feed_tab(feed_tab, win)
        self._build_category_tab(cat_tab)

        # --- Bottom toolbar ---
        toolbar = ttk.Frame(win, padding="8 4")
        toolbar.pack(fill=tk.X)

        ttk.Button(toolbar, text="Refresh",
                   command=lambda: self._refresh_health_tree(feed_tree)).pack(side=tk.LEFT, padx=4)
        ttk.Button(toolbar, text="Export to CSV",
                   command=lambda: self._export_health_csv(win)).pack(side=tk.LEFT, padx=4)
        ttk.Button(toolbar, text="Export Diagnostics",
                   command=lambda: self._export_diagnostics_report(win)).pack(side=tk.LEFT, padx=4)

        ttk.Separator(toolbar, orient='vertical').pack(side=tk.LEFT, fill=tk.Y, padx=6)

        ttk.Button(
            toolbar, text="Copy Selected URLs",
            command=lambda: self._copy_selected_urls(feed_tree, win),
        ).pack(side=tk.LEFT, padx=4)
        ttk.Button(
            toolbar, text="Remove Selected",
            command=lambda: self._remove_selected_from_dashboard(feed_tree, win),
        ).pack(side=tk.LEFT, padx=4)

        ttk.Label(
            toolbar,
            text="Ctrl+click or Shift+click to select multiple rows  |  right-click for options",
            font=("Arial", 8), foreground="gray",
        ).pack(side=tk.LEFT, padx=12)

    # ------------------------------------------------------------------
    # By-Feed tab
    # ------------------------------------------------------------------

    def _build_feed_tab(self, parent, win):
        """Build the per-feed treeview.  Returns the tree widget."""
        cols = ('status', 'url', 'category', 'success_rate', 'avg_articles',
                'consec_fails', 'last_published', 'last_success', 'last_error', 'note')

        tree_frame = ttk.Frame(parent)
        tree_frame.pack(fill=tk.BOTH, expand=True)

        scroll_y = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL)
        scroll_x = ttk.Scrollbar(tree_frame, orient=tk.HORIZONTAL)

        tree = ttk.Treeview(
            tree_frame,
            columns=cols,
            show='headings',
            yscrollcommand=scroll_y.set,
            xscrollcommand=scroll_x.set,
            selectmode='extended',
        )
        scroll_y.config(command=tree.yview)
        scroll_x.config(command=tree.xview)
        scroll_y.pack(side=tk.RIGHT,  fill=tk.Y)
        scroll_x.pack(side=tk.BOTTOM, fill=tk.X)
        tree.pack(fill=tk.BOTH, expand=True)

        headings = {
            'status':         ('Status',         90, tk.CENTER),
            'url':            ('Feed URL',       300, tk.W),
            'category':       ('Category',       110, tk.W),
            'success_rate':   ('Success Rate',    85, tk.CENTER),
            'avg_articles':   ('Avg Articles',    85, tk.CENTER),
            'consec_fails':   ('Consec. Fails',   85, tk.CENTER),
            'last_published': ('Last Published', 130, tk.CENTER),
            'last_success':   ('Last Success',   140, tk.CENTER),
            'last_error':     ('Last Error',     140, tk.CENTER),
            'note':           ('Note',           180, tk.W),
        }
        for col, (label, width, anchor) in headings.items():
            tree.heading(col, text=label,
                         command=lambda c=col: self._sort_health_tree(tree, c, False))
            tree.column(col, width=width, anchor=anchor, minwidth=50)

        # Health status row colours (row-level tags)
        for status, bg in FeedHealthDB.STATUS_COLOURS.items():
            tree.tag_configure(status.lower(), background=bg)

        self._refresh_health_tree(tree)

        # --- Interactions ---

        def on_double_click(event):
            item = tree.focus()
            if not item:
                return
            url_val = tree.item(item, 'values')[1]
            self.root.clipboard_clear()
            self.root.clipboard_append(url_val)
            self.root.update()
            win.title("Feed Health Dashboard  —  URL copied!")
            win.after(1800, lambda: win.title("Feed Health Dashboard"))

        def on_right_click(event):
            row = tree.identify_row(event.y)
            if not row:
                return
            tree.selection_set(row)
            tree.focus(row)
            ctx = tk.Menu(tree, tearoff=0)
            ctx.add_command(label="Edit Note...",
                            command=lambda: self._open_note_editor(tree, row))
            ctx.add_command(label="Copy URL",
                            command=lambda: self._copy_url_from_row(tree, row, win))
            ctx.add_separator()
            ctx.add_command(label="Remove Feed...",
                            command=lambda: self._remove_feed_from_dashboard(tree, [row], win))
            try:
                ctx.tk_popup(event.x_root, event.y_root)
            finally:
                ctx.grab_release()

        tree.bind("<Double-1>", on_double_click)
        tree.bind("<Button-3>", on_right_click)

        return tree

    def _refresh_health_tree(self, tree):
        """Clear and repopulate the By-Feed treeview from the current DB."""
        for row in tree.get_children():
            tree.delete(row)

        for url, entry in self.health_db.data.items():
            status       = self.health_db.get_status(url)
            note         = entry.get('note', '')
            note_display = (note[:35] + '...') if len(note) > 35 else note

            tree.insert('', tk.END, iid=url, values=(
                status,
                url,
                entry.get('category', '—'),
                self.health_db.get_success_rate_str(url),
                self.health_db.get_avg_articles_str(url),
                entry.get('consecutive_failures', 0),
                self.health_db.get_staleness_col_str(url),
                entry.get('last_success') or '—',
                entry.get('last_error')   or '—',
                note_display,
            ), tags=(status.lower(),))

    def _sort_health_tree(self, tree, col, reverse):
        """Sort the By-Feed treeview rows by the given column."""
        rows = [(tree.set(child, col), child) for child in tree.get_children('')]
        try:
            rows.sort(
                key=lambda x: float(x[0]) if x[0] not in ('—', '', 'Never seen') else -1.0,
                reverse=reverse,
            )
        except ValueError:
            rows.sort(key=lambda x: x[0].lower(), reverse=reverse)
        for index, (_, child) in enumerate(rows):
            tree.move(child, '', index)
        tree.heading(col, command=lambda: self._sort_health_tree(tree, col, not reverse))

    def _open_note_editor(self, tree, iid):
        """Open a dialog to edit the annotation for a feed (iid == URL)."""
        url      = iid
        existing = self.health_db.get_note(url)

        new_note = simpledialog.askstring(
            "Edit Note",
            f"Note for:\n{url[:80]}\n",
            initialvalue=existing,
            parent=self.root,
        )
        if new_note is None:
            return   # user cancelled

        self.health_db.set_note(url, new_note)
        self.health_db.save()

        # Update the treeview row immediately without a full refresh
        display = (new_note[:35] + '...') if len(new_note) > 35 else new_note
        vals    = list(tree.item(iid, 'values'))
        vals[9] = display   # 'note' is column index 9
        tree.item(iid, values=vals)

    def _copy_url_from_row(self, tree, iid, win):
        """Copy the URL from a treeview row to the clipboard."""
        url_val = tree.item(iid, 'values')[1]
        self.root.clipboard_clear()
        self.root.clipboard_append(url_val)
        self.root.update()
        win.title("Feed Health Dashboard  --  URL copied!")
        win.after(1800, lambda: win.title("Feed Health Dashboard"))

    def _remove_feed_from_dashboard(self, tree, iids, win):
        """Remove one or more feeds from valid_sources.txt and the health DB.

        Args:
            tree:  The By-Feed treeview.
            iids:  List of treeview item IDs (== URL strings).
            win:   The dashboard toplevel window (for dialog parenting).
        """
        urls = [tree.item(iid, 'values')[1] for iid in iids]
        if not urls:
            return

        preview = "\n".join(f"  {u[:80]}" for u in urls[:6])
        if len(urls) > 6:
            preview += f"\n  ... and {len(urls) - 6} more"

        if not messagebox.askyesno(
            "Confirm Removal",
            f"Remove {len(urls)} feed(s) from {SOURCE_FILE} and the health database?\n\n{preview}",
            parent=win,
        ):
            return

        removed, not_found = self._remove_urls_from_sources(urls)
        self.health_db.remove_urls(removed)
        self.health_db.save()

        # Remove rows from the treeview immediately — no full refresh needed.
        for iid in iids:
            url = tree.item(iid, 'values')[1]
            if url in removed:
                tree.delete(iid)

        summary = f"Removed {len(removed)} feed(s)."
        if not_found:
            summary += f"\n\n{len(not_found)} URL(s) were not in {SOURCE_FILE} (health DB entry still cleared)."
        messagebox.showinfo("Done", summary, parent=win)

    def _copy_selected_urls(self, tree, win):
        """Copy the URLs of all currently selected rows to the clipboard, one per line."""
        selected = tree.selection()
        if not selected:
            messagebox.showinfo("Nothing Selected",
                                "Select one or more rows first (Ctrl+click or Shift+click).",
                                parent=win)
            return
        urls = [tree.item(iid, 'values')[1] for iid in selected]
        self.root.clipboard_clear()
        self.root.clipboard_append("\n".join(urls))
        self.root.update()
        win.title(f"Feed Health Dashboard  --  {len(urls)} URL(s) copied!")
        win.after(2000, lambda: win.title("Feed Health Dashboard"))

    def _remove_selected_from_dashboard(self, tree, win):
        """Remove all currently selected rows from valid_sources.txt and the health DB."""
        selected = tree.selection()
        if not selected:
            messagebox.showinfo("Nothing Selected",
                                "Select one or more rows first (Ctrl+click or Shift+click).",
                                parent=win)
            return
        self._remove_feed_from_dashboard(tree, list(selected), win)

    # ------------------------------------------------------------------
    # By-Category tab
    # ------------------------------------------------------------------

    def _build_category_tab(self, parent):
        """Build the category-rollup treeview inside the By Category tab."""
        cols = ('category', 'total', 'good', 'unstable', 'poor', 'dead',
                'new_feeds', 'avg_success', 'freshest', 'stalest')

        tree_frame = ttk.Frame(parent)
        tree_frame.pack(fill=tk.BOTH, expand=True)

        scroll_y = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL)
        tree = ttk.Treeview(
            tree_frame,
            columns=cols,
            show='headings',
            yscrollcommand=scroll_y.set,
            selectmode='browse',
        )
        scroll_y.config(command=tree.yview)
        scroll_y.pack(side=tk.RIGHT, fill=tk.Y)
        tree.pack(fill=tk.BOTH, expand=True)

        headings = {
            'category':   ('Category',         200, tk.W),
            'total':      ('Total Feeds',        90, tk.CENTER),
            'good':       ('Good',               60, tk.CENTER),
            'unstable':   ('Unstable',           65, tk.CENTER),
            'poor':       ('Poor',               60, tk.CENTER),
            'dead':       ('Dead',               60, tk.CENTER),
            'new_feeds':  ('New',                60, tk.CENTER),
            'avg_success':('Avg Success Rate',  120, tk.CENTER),
            'freshest':   ('Freshest Article',  130, tk.CENTER),
            'stalest':    ('Stalest Article',   130, tk.CENTER),
        }
        for col, (label, width, anchor) in headings.items():
            tree.heading(col, text=label,
                         command=lambda c=col: self._sort_cat_tree(tree, c, False))
            tree.column(col, width=width, anchor=anchor, minwidth=50)

        # Row colours: any dead feeds = pink, any unstable/poor = amber, else green
        tree.tag_configure('cat_healthy',  background='#d4edda')
        tree.tag_configure('cat_warning',  background='#fff3cd')
        tree.tag_configure('cat_critical', background='#f8d7da')

        for row in self.health_db.get_category_summary():
            if row['dead'] > 0:
                tag = 'cat_critical'
            elif row['unstable'] > 0 or row['poor'] > 0:
                tag = 'cat_warning'
            else:
                tag = 'cat_healthy'

            tree.insert('', tk.END, values=(
                row['category'],
                row['total_feeds'],
                row['good'],
                row['unstable'],
                row['poor'],
                row['dead'],
                row['new_feeds'],
                row['avg_success_rate'],
                row['freshest_date'],
                row['stalest_date'],
            ), tags=(tag,))

        ttk.Label(
            parent,
            text="Row colours: Green = all healthy  |  Amber = some unstable/poor  |  Red = has dead feed(s)",
            font=("Arial", 8), foreground="gray",
        ).pack(pady=(2, 4))

    def _sort_cat_tree(self, tree, col, reverse):
        """Sort the By-Category treeview by the given column."""
        rows = [(tree.set(child, col), child) for child in tree.get_children('')]
        try:
            rows.sort(
                key=lambda x: float(x[0].replace('%', '')) if x[0] not in ('—', '') else -1.0,
                reverse=reverse,
            )
        except ValueError:
            rows.sort(key=lambda x: x[0].lower(), reverse=reverse)
        for index, (_, child) in enumerate(rows):
            tree.move(child, '', index)
        tree.heading(col, command=lambda: self._sort_cat_tree(tree, col, not reverse))

    # ------------------------------------------------------------------
    # CSV Export
    # ------------------------------------------------------------------

    def _export_health_csv(self, parent_win):
        """Export the full feed health data to a CSV file chosen by the user."""
        file_path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV Files", "*.csv"), ("All Files", "*.*")],
            title="Export Feed Health to CSV",
            parent=parent_win,
        )
        if not file_path:
            return

        fieldnames = [
            'url', 'category', 'status', 'success_rate', 'avg_articles_per_scan',
            'consecutive_failures', 'total_scans', 'total_successes', 'total_articles',
            'last_published', 'last_article_date', 'last_success', 'last_error',
            'last_error_msg', 'first_seen', 'note',
        ]

        try:
            with open(file_path, 'w', newline='', encoding='utf-8-sig') as fh:
                writer = csv.DictWriter(fh, fieldnames=fieldnames, extrasaction='ignore')
                writer.writeheader()

                for url, entry in self.health_db.data.items():
                    total = entry.get('total_scans', 0)
                    succ  = entry.get('total_successes', 0)
                    arts  = entry.get('total_articles', 0)
                    writer.writerow({
                        'url':                   url,
                        'category':              entry.get('category', ''),
                        'status':                self.health_db.get_status(url),
                        'success_rate':          f"{succ}/{total}" if total else '0/0',
                        'avg_articles_per_scan': round(arts / succ, 1) if succ else 0,
                        'consecutive_failures':  entry.get('consecutive_failures', 0),
                        'total_scans':           total,
                        'total_successes':       succ,
                        'total_articles':        arts,
                        'last_published':        self.health_db.get_staleness_col_str(url),
                        'last_article_date':     entry.get('last_article_date') or '',
                        'last_success':          entry.get('last_success')      or '',
                        'last_error':            entry.get('last_error')        or '',
                        'last_error_msg':        entry.get('last_error_msg')    or '',
                        'first_seen':            entry.get('first_seen')        or '',
                        'note':                  entry.get('note', ''),
                    })

            messagebox.showinfo("Exported",
                                f"Feed health exported to:\n{file_path}",
                                parent=parent_win)
        except OSError as e:
            messagebox.showerror("Export Failed", f"Could not write CSV:\n{e}",
                                 parent=parent_win)

    def _export_diagnostics_report(self, parent_win):
        """Write a plain-text diagnostics report combining:
            - Section 1: Feeds with no article date ever recorded ('Never seen')
            - Section 2: All feeds that have ever produced an error, with full details
        Intended to be shared for troubleshooting broken or silent feeds.
        """
        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")],
            title="Save Diagnostics Report",
            parent=parent_win,
        )
        if not file_path:
            return

        now_str      = datetime.now().strftime('%Y-%m-%d %H:%M')
        never_seen   = []
        error_feeds  = []

        for url, entry in self.health_db.data.items():
            if not entry.get('last_article_date'):
                never_seen.append((url, entry))
            if entry.get('last_error_msg'):
                error_feeds.append((url, entry))

        # Sort both lists by category then URL for readability
        never_seen.sort(key=lambda x: (x[1].get('category', ''), x[0]))
        error_feeds.sort(key=lambda x: (-x[1].get('consecutive_failures', 0), x[0]))

        try:
            with open(file_path, 'w', encoding='utf-8') as fh:
                fh.write(f"OSINT SCANNER DIAGNOSTICS REPORT\n")
                fh.write(f"Generated: {now_str}\n")
                fh.write(f"Total feeds tracked: {len(self.health_db.data)}\n")
                fh.write("=" * 70 + "\n\n")

                # --- Section 1: Never Seen ---
                fh.write(f"SECTION 1 — NEVER SEEN ({len(never_seen)} feeds)\n")
                fh.write("These feeds have never returned a parseable article date.\n")
                fh.write("Possible causes: feed is empty, date fields are missing, or the\n")
                fh.write("feed format is non-standard. Check the URL manually.\n")
                fh.write("-" * 70 + "\n\n")

                if never_seen:
                    for url, entry in never_seen:
                        fh.write(f"URL:       {url}\n")
                        fh.write(f"Category:  {entry.get('category', 'Unknown')}\n")
                        fh.write(f"Status:    {self.health_db.get_status(url)}\n")
                        fh.write(f"Scans:     {entry.get('total_scans', 0)} total, "
                                 f"{entry.get('total_successes', 0)} successful\n")
                        fh.write(f"First seen:{entry.get('first_seen', 'Unknown')}\n")
                        if entry.get('last_error_msg'):
                            fh.write(f"Last error:{entry.get('last_error_msg')}\n")
                        fh.write("\n")
                else:
                    fh.write("None — all tracked feeds have returned at least one article date.\n\n")

                # --- Section 2: Error History ---
                fh.write("=" * 70 + "\n\n")
                fh.write(f"SECTION 2 — ERROR HISTORY ({len(error_feeds)} feeds with errors)\n")
                fh.write("Sorted by consecutive failures (worst first).\n")
                fh.write("-" * 70 + "\n\n")

                if error_feeds:
                    for url, entry in error_feeds:
                        cf = entry.get('consecutive_failures', 0)
                        fh.write(f"URL:              {url}\n")
                        fh.write(f"Category:         {entry.get('category', 'Unknown')}\n")
                        fh.write(f"Status:           {self.health_db.get_status(url)}\n")
                        fh.write(f"Consec. failures: {cf}\n")
                        fh.write(f"Success rate:     {self.health_db.get_success_rate_str(url)}\n")
                        fh.write(f"Last error time:  {entry.get('last_error', 'Unknown')}\n")
                        fh.write(f"Last error msg:   {entry.get('last_error_msg', 'Unknown')}\n")
                        fh.write("\n")
                else:
                    fh.write("None — no feeds have recorded errors yet.\n\n")

            messagebox.showinfo("Diagnostics Saved",
                                f"Report saved to:\n{file_path}\n\n"
                                f"{len(never_seen)} never-seen feed(s)\n"
                                f"{len(error_feeds)} feed(s) with error history",
                                parent=parent_win)
        except OSError as e:
            messagebox.showerror("Export Failed", f"Could not write report:\n{e}",
                                 parent=parent_win)

    # ------------------------------------------------------------------
    # DEAD FEED MANAGER
    # ------------------------------------------------------------------

    def open_dead_feed_manager(self, auto_prompt=False):
        """Open a dialog listing dead feeds with checkboxes to remove them."""
        dead = self.health_db.get_dead_feeds(DEAD_FEED_THRESHOLD)

        active_urls = set()
        if os.path.exists(SOURCE_FILE):
            with open(SOURCE_FILE, 'r', encoding='utf-8') as fh:
                for line in fh:
                    clean = line.strip()
                    if clean and not clean.startswith('#') and \
                            not (clean.startswith('[') and clean.endswith(']')):
                        active_urls.add(clean)

        dead_in_sources = {url: e for url, e in dead.items() if url in active_urls}

        if not dead_in_sources:
            if not auto_prompt:
                messagebox.showinfo(
                    "Dead Feed Manager",
                    f"No dead feeds found in your source list.\n\n"
                    f"A feed is marked dead after {DEAD_FEED_THRESHOLD} consecutive "
                    f"failures.\nRun a scan to start collecting data.",
                )
            return

        title = ("Dead Feeds Detected After Scan" if auto_prompt
                 else "Dead Feed Manager")

        win = tk.Toplevel(self.root)
        win.title(title)
        win.geometry("840x520")
        win.resizable(True, True)
        win.grab_set()

        hdr = ttk.Frame(win, padding="12 10 12 4")
        hdr.pack(fill=tk.X)
        ttk.Label(
            hdr,
            text=f"  {len(dead_in_sources)} feed(s) have failed {DEAD_FEED_THRESHOLD}+ scans in a row.",
            font=("Arial", 11, "bold"),
            foreground="#c0392b",
        ).pack(anchor='w')
        ttk.Label(
            hdr,
            text="  Tick the ones you want to remove from your sources list, then click Remove Selected.",
            font=("Arial", 9),
            foreground="gray",
        ).pack(anchor='w', pady=(2, 0))
        ttk.Separator(win, orient='horizontal').pack(fill=tk.X, padx=10, pady=4)

        container = ttk.Frame(win)
        container.pack(fill=tk.BOTH, expand=True, padx=10)

        canvas  = tk.Canvas(container, borderwidth=0, background="#f9f9f9")
        vscroll = ttk.Scrollbar(container, orient=tk.VERTICAL, command=canvas.yview)
        inner   = ttk.Frame(canvas, padding="4")
        inner.bind("<Configure>",
                   lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=inner, anchor='nw')
        canvas.configure(yscrollcommand=vscroll.set)
        vscroll.pack(side=tk.RIGHT, fill=tk.Y)
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        col_hdr = ttk.Frame(inner)
        col_hdr.pack(fill=tk.X, pady=(0, 3))
        ttk.Label(col_hdr, text="Remove", width=7,  font=("Arial", 9, "bold")).pack(side=tk.LEFT)
        ttk.Label(col_hdr, text="Feed URL",         font=("Arial", 9, "bold"), width=52).pack(side=tk.LEFT)
        ttk.Label(col_hdr, text="Fails",  width=6,  font=("Arial", 9, "bold")).pack(side=tk.LEFT)
        ttk.Label(col_hdr, text="Last Error",       font=("Arial", 9, "bold")).pack(side=tk.LEFT)
        ttk.Separator(inner, orient='horizontal').pack(fill=tk.X, pady=2)

        check_vars  = {}
        sorted_dead = sorted(dead_in_sources.items(),
                             key=lambda x: -x[1].get('consecutive_failures', 0))

        for url, entry in sorted_dead:
            row = ttk.Frame(inner, padding="2 3")
            row.pack(fill=tk.X)

            var = tk.BooleanVar(value=True)
            check_vars[url] = var

            ttk.Checkbutton(row, variable=var, width=2).pack(side=tk.LEFT, padx=(0, 6))

            display_url = url if len(url) <= 58 else url[:55] + "..."
            lbl = ttk.Label(row, text=display_url, width=52,
                            font=("Consolas", 9), foreground="#2c3e50")
            lbl.pack(side=tk.LEFT)
            lbl.bind("<Enter>", lambda e, u=url: win.title(u))
            lbl.bind("<Leave>", lambda e: win.title(title))

            cf = entry.get('consecutive_failures', 0)
            ttk.Label(row, text=str(cf), width=6,
                      font=("Arial", 9, "bold"), foreground="#c0392b").pack(side=tk.LEFT)

            err_short = (entry.get('last_error_msg') or '—')[:65]
            ttk.Label(row, text=err_short,
                      font=("Arial", 9), foreground="gray").pack(side=tk.LEFT, padx=(4, 0))

            ttk.Separator(inner, orient='horizontal').pack(fill=tk.X)

        btn_frame = ttk.Frame(win, padding="10 8")
        btn_frame.pack(fill=tk.X)

        def select_all():
            for v in check_vars.values():
                v.set(True)

        def deselect_all():
            for v in check_vars.values():
                v.set(False)

        def remove_selected():
            to_remove = [u for u, v in check_vars.items() if v.get()]
            if not to_remove:
                messagebox.showwarning("Nothing Selected",
                                       "No feeds are checked. Tick at least one to remove.",
                                       parent=win)
                return
            preview = "\n".join(f"  • {u[:75]}" for u in to_remove[:8])
            if len(to_remove) > 8:
                preview += f"\n  ... and {len(to_remove) - 8} more"
            if not messagebox.askyesno(
                "Confirm Removal",
                f"Remove {len(to_remove)} feed(s) from {SOURCE_FILE}?\n\n{preview}",
                parent=win,
            ):
                return
            removed, not_found = self._remove_urls_from_sources(to_remove)
            self.health_db.remove_urls(removed)
            self.health_db.save()
            summary = f"Removed {len(removed)} feed(s) from {SOURCE_FILE}."
            if not_found:
                summary += f"\n\n{len(not_found)} URL(s) were not found (possibly already removed)."
            messagebox.showinfo("Done", summary, parent=win)
            win.destroy()

        ttk.Button(btn_frame, text="Select All",       command=select_all).pack(side=tk.LEFT,  padx=4)
        ttk.Button(btn_frame, text="Deselect All",     command=deselect_all).pack(side=tk.LEFT, padx=4)
        ttk.Button(btn_frame, text="Remove Selected",  command=remove_selected).pack(side=tk.RIGHT, padx=4)
        ttk.Button(btn_frame, text="Keep All / Close", command=win.destroy).pack(side=tk.RIGHT, padx=4)

    def _remove_urls_from_sources(self, urls_to_remove):
        """Remove specific URLs from valid_sources.txt.  Returns (removed, not_found)."""
        remove_set = set(urls_to_remove)
        removed    = []
        not_found  = set(remove_set)   # shrinks as matches are found
        new_lines  = []
        try:
            with open(SOURCE_FILE, 'r', encoding='utf-8') as fh:
                for line in fh:
                    stripped = line.strip()
                    if stripped in remove_set:
                        removed.append(stripped)
                        not_found.discard(stripped)
                    else:
                        new_lines.append(line)
            with open(SOURCE_FILE, 'w', encoding='utf-8') as fh:
                fh.writelines(new_lines)
        except OSError as e:
            messagebox.showerror("File Error", f"Could not modify {SOURCE_FILE}:\n{e}")
            return [], list(urls_to_remove)
        return removed, list(not_found)

    # ------------------------------------------------------------------
    # STANDARD GUI METHODS
    # ------------------------------------------------------------------

    def show_context_menu(self, event):
        try:
            self.context_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.context_menu.grab_release()

    def copy_selection(self):
        """Copy highlighted text from the log area to the system clipboard."""
        if self.log_area.tag_ranges(tk.SEL):
            selected_text = self.log_area.get(tk.SEL_FIRST, tk.SEL_LAST)
            self.root.clipboard_clear()
            self.root.clipboard_append(selected_text)
            self.root.update()

    def open_source_editor(self):
        """Open a modal editor window for valid_sources.txt."""
        editor_window = tk.Toplevel(self.root)
        editor_window.title("Source Editor")
        editor_window.geometry("600x600")
        editor_window.grab_set()

        text_area = scrolledtext.ScrolledText(editor_window, font=("Consolas", 10))
        text_area.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        if os.path.exists(SOURCE_FILE):
            with open(SOURCE_FILE, 'r', encoding='utf-8') as fh:
                text_area.insert(1.0, fh.read())

        def save_sources():
            try:
                with open(SOURCE_FILE, 'w', encoding='utf-8') as fh:
                    fh.write(text_area.get(1.0, tk.END))
                messagebox.showinfo("Saved", "Sources saved successfully!", parent=editor_window)
                editor_window.destroy()
            except OSError as e:
                messagebox.showerror("Error", f"Failed to save:\n{e}", parent=editor_window)

        ttk.Button(editor_window, text="Save & Close", command=save_sources).pack(pady=10)

    def save_as_file(self):
        """Prompt the user for a path and save the current log area contents."""
        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")],
            title="Save Report As",
        )
        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as fh:
                    fh.write(self.log_area.get(1.0, tk.END))
                messagebox.showinfo("Saved", f"File saved successfully:\n{file_path}")
            except OSError as e:
                messagebox.showerror("Error", f"Could not save file:\n{e}")

    def copy_all(self):
        """Copy the entire log area text to the clipboard."""
        self.root.clipboard_clear()
        self.root.clipboard_append(self.log_area.get(1.0, tk.END))
        messagebox.showinfo("Copied", "All results copied to clipboard.")

    def open_search(self):
        """Open a search dialog, highlight matches in the log, and show a results popup."""
        query = simpledialog.askstring("Search", "Enter text to find:", parent=self.root)
        if not query:
            return

        self.log_area.tag_remove('search', '1.0', tk.END)
        results_found = []

        for line_num, line in enumerate(self.log_area.get(1.0, tk.END).split('\n'), 1):
            if query.lower() in line.lower():
                results_found.append(f"Line {line_num}: {line.strip()}")

        if not results_found:
            messagebox.showinfo("Search", "No matches found.")
            return

        idx = '1.0'
        while True:
            idx = self.log_area.search(query, idx, nocase=1, stopindex=tk.END)
            if not idx:
                break
            lastidx = f"{idx}+{len(query)}c"
            self.log_area.tag_add('search', idx, lastidx)
            idx = lastidx
        self.log_area.tag_config('search', background='yellow', foreground='black')

        search_window = tk.Toplevel(self.root)
        search_window.title(f"Search Results for: '{query}'")
        search_window.geometry("800x400")

        results_area = scrolledtext.ScrolledText(search_window, font=("Consolas", 10), wrap=tk.WORD)
        results_area.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        for res in results_found:
            results_area.insert(tk.END, res + "\n\n")
        results_area.config(state='disabled')

    def jump_to_category(self, event=None):
        """Scroll the log area to the selected category header."""
        selection = self.nav_var.get()
        if selection in self.category_indices:
            self.log_area.see(self.category_indices[selection])

    # ------------------------------------------------------------------
    # THREAD-SAFE QUEUE MESSAGING
    # ------------------------------------------------------------------

    def log(self, message, tag="INFO"):
        """Queue a log message for display on the GUI thread."""
        self.queue.put(("log", (message, tag)))

    def update_progress(self, value, max_val):
        """Queue a progress bar update."""
        self.queue.put(("progress", (value, max_val)))

    def scan_finished(self):
        """Queue the scan-complete signal."""
        self.queue.put(("done", None))

    def prompt_dead_feeds(self):
        """Queue a signal to open the dead feed manager after the scan is done."""
        self.queue.put(("dead_feeds", None))

    def process_queue(self):
        """Drain the inter-thread message queue and update the GUI.

        This is the ONLY method that touches GUI widgets, keeping all
        widget access on the main thread (Tkinter is not thread-safe).
        """
        try:
            while True:
                msg_type, data = self.queue.get_nowait()

                if msg_type == "log":
                    text, tag = data
                    self.log_area.config(state='normal')
                    if tag == "HEADER":
                        start_index = self.log_area.index(tk.INSERT)
                        clean_name  = text.strip(" #\n")
                        self.category_indices[clean_name] = start_index
                        self.nav_combo['values'] = list(self.category_indices.keys())
                    self.log_area.insert(tk.END, text + "\n", tag)
                    self.log_area.see(tk.END)
                    self.log_area.config(state='disabled')

                elif msg_type == "progress":
                    curr, total = data
                    self.progress['maximum'] = total
                    self.progress['value']   = curr
                    self.lbl_status.config(text=f"Scanning... ({curr}/{total})")

                elif msg_type == "done":
                    elapsed = datetime.now() - self._scan_start
                    mins, secs = divmod(int(elapsed.total_seconds()), 60)
                    elapsed_str = f"{mins}m {secs}s" if mins else f"{secs}s"
                    self.lbl_status.config(text=f"Scan Complete  |  Duration: {elapsed_str}")
                    self.btn_scan.config(state='normal')
                    self.btn_edit.config(state='normal')
                    self.log_area.see('1.0')

                elif msg_type == "dead_feeds":
                    self.open_dead_feed_manager(auto_prompt=True)

        except queue.Empty:
            pass

        self.root.after(100, self.process_queue)

    # ------------------------------------------------------------------
    # SCAN THREAD
    # ------------------------------------------------------------------

    def start_scan_thread(self):
        """Disable buttons, clear the log, and launch the scan in a background thread."""
        self._scan_start = datetime.now()
        self.btn_scan.config(state='disabled')
        self.btn_edit.config(state='disabled')

        self.category_indices.clear()
        self.nav_combo.set('')
        self.nav_combo['values'] = []

        self.log_area.config(state='normal')
        self.log_area.delete(1.0, tk.END)
        self.log_area.config(state='disabled')

        thread = threading.Thread(target=self.run_logic, daemon=True)
        thread.start()

    def run_logic(self):
        """Main scan logic — runs entirely in a background thread."""
        if not os.path.exists(SOURCE_FILE):
            self.log(f"[!] Error: Could not find '{SOURCE_FILE}'", "ERROR")
            self.scan_finished()
            return

        source_list      = []
        current_category = "Uncategorized"

        with open(SOURCE_FILE, 'r', encoding='utf-8') as fh:
            for line in fh:
                clean = line.strip()
                if not clean or clean.startswith('#'):
                    continue
                if clean.startswith('[') and clean.endswith(']'):
                    current_category = clean[1:-1]
                    continue
                source_list.append((current_category, clean))

        total_sources = len(source_list)
        self.log(f"--- Loaded {total_sources} sources ---", "INFO")

        cutoff, mode = get_cutoff_time()
        self.log(f"--- Mode: {mode} ---", "INFO")

        category_findings    = {}
        dead_sites           = []
        priority_findings    = []
        processed_count      = 0
        total_findings_count = 0
        seen_links           = set()
        site_article_counts  = {}   # {site_title: count} for top-source reporting

        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = {
                executor.submit(process_single_feed, src, cutoff): src
                for src in source_list
            }

            for future in concurrent.futures.as_completed(futures):
                orig_cat, orig_url = futures[future]
                cat, found_data, error_data = future.result()
                processed_count += 1
                self.update_progress(processed_count, total_sources)

                # --- Record health ---
                if error_data:
                    dead_sites.append(error_data)
                    self.health_db.record_failure(
                        orig_url, orig_cat,
                        error_data.get('error', 'Unknown error'),
                    )
                else:
                    article_count       = found_data.get('article_count', 0) if found_data else 0
                    newest_article_date = found_data.get('newest_article_date') if found_data else None
                    self.health_db.record_success(
                        orig_url, orig_cat, article_count,
                        newest_article_date=newest_article_date,
                    )

                # --- Deduplicate and collect ---
                if found_data and found_data.get('articles'):
                    filtered_articles = []
                    for article in found_data['articles']:
                        if article['link'] in seen_links:
                            continue
                        seen_links.add(article['link'])
                        filtered_articles.append(article)
                        total_findings_count += 1

                        if article['priority_terms']:
                            priority_findings.append({
                                'site':    found_data['site_title'],
                                'article': article,
                            })
                            terms_str = ", ".join(article['priority_terms'])
                            self.log(
                                f"[!] PRIORITY ALERT [Matched: {terms_str}]: {article['title']}",
                                "ALERT",
                            )

                    if filtered_articles:
                        category_findings.setdefault(cat, [])
                        found_data['articles'] = filtered_articles
                        category_findings[cat].append(found_data)
                        # Accumulate for top-source reporting
                        title_key = found_data.get('site_title', orig_url)
                        site_article_counts[title_key] = (
                            site_article_counts.get(title_key, 0) + len(filtered_articles)
                        )

        self.health_db.save()

        # --- Write report ---
        self.log("\n" + "=" * 50, "INFO")
        self.log("Scan Finished. Generating Report...", "INFO")
        self.log("=" * 50 + "\n", "INFO")

        current_dt_str  = datetime.now().strftime('%Y-%m-%d_%H%M')
        output_filename = f"daily_osint_{current_dt_str}.txt"

        try:
            with open(output_filename, 'w', encoding='utf-8') as fh:
                fh.write(f"OSINT DAILY REPORT - {current_dt_str}\n")
                fh.write(f"Scan Mode: {mode}\n\n")

                if priority_findings:
                    header = "### HIGH PRIORITY ALERTS ###"
                    fh.write(header + "\n\n")
                    self.log(header, "HEADER")
                    for item in priority_findings:
                        art       = item['article']
                        terms_str = ", ".join(art['priority_terms'])
                        msg = (
                            f"ALERT: {art['title']}\n"
                            f"MATCHED: {terms_str}\n"
                            f"LINK: {art['link']}\n"
                            f"IOC: {'Yes' if art['has_ioc'] else 'No'}\n"
                        )
                        fh.write(msg + "\n")
                        self.log(msg, "ALERT")

                for cat, sites in category_findings.items():
                    cat_header = f"### {cat.upper()} ###"
                    fh.write(cat_header + "\n\n")
                    self.log("\n" + cat_header, "HEADER")
                    for site in sites:
                        fh.write(f"SOURCE: {site['site_title']}\n")
                        for art in site['articles']:
                            art_msg = (
                                f"TITLE: {art['title']}\n"
                                f"LINK: {art['link']}\n"
                                f"IOC: {'Yes' if art['has_ioc'] else 'No'}\n"
                            )
                            fh.write(art_msg + "\n")
                            self.log(art_msg)

                if dead_sites:
                    fh.write("\n### FAILED FEEDS THIS SCAN ###\n\n")
                    for d in dead_sites:
                        fh.write(f"URL: {d['url']}\nERROR: {d['error']}\n\n")

            self.log(f"\n--- Report Saved: {output_filename} ---", "SUCCESS")
            self.log(f"Total Unique Articles Found: {total_findings_count}", "INFO")

            if dead_sites:
                self.log(f"--- {len(dead_sites)} feed(s) failed this scan ---", "ERROR")

            dead_count = len(self.health_db.get_dead_feeds(DEAD_FEED_THRESHOLD))
            self.log(
                f"--- Feed Health: {len(self.health_db.data)} tracked, "
                f"{dead_count} dead (>={DEAD_FEED_THRESHOLD} consecutive failures) ---",
                "INFO",
            )

            if site_article_counts:
                top_site  = max(site_article_counts, key=site_article_counts.get)
                top_count = site_article_counts[top_site]
                self.log(f"--- Top Source: {top_site} ({top_count} article(s)) ---", "INFO")

        except OSError as e:
            self.log(f"Error writing file: {e}", "ERROR")

        self.scan_finished()

        # Check if any dead feeds are still present in the source list we already loaded.
        scanned_urls = {url for _, url in source_list}
        if any(url in scanned_urls
               for url in self.health_db.get_dead_feeds(DEAD_FEED_THRESHOLD)):
            self.prompt_dead_feeds()


# ---------------------------------------------------------------------------
# ENTRY POINT
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    root = tk.Tk()
    app  = OSINTApp(root)
    root.mainloop()
