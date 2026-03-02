import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog, simpledialog
import threading
import queue
import os
import sys
import ssl
import json
import socket
import urllib.request
import urllib.error
import urllib.parse
import email.utils
import gzip
import re
import concurrent.futures
from datetime import datetime, timedelta, timezone


# ---------------------------------------------------------------------------
# CONFIGURATION LOADER
# Reads settings from config.json sitting next to this script.
# If the file is missing or a key is absent, safe defaults are used so the
# tool still runs — but you should fix config.json when you get a chance.
# ---------------------------------------------------------------------------

CONFIG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")
HEALTH_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "feed_health.json")

_DEFAULTS = {
    "your_email":          "nbawysvcrgjhmgbgcc@nesopf.com",
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

# Hash patterns alone match too many innocent hex strings (UUIDs, CSS colours, etc.).
# Only flag them when these context words appear nearby.
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
# Persists per-URL statistics across scans in feed_health.json.
# All writes happen at scan-end on the main thread, so no locking is needed.
# ---------------------------------------------------------------------------

def _now_str():
    """Return the current UTC time as a readable string."""
    return datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')


class FeedHealthDB:
    """Tracks per-feed health statistics and persists them to feed_health.json."""

    # Row background colours used by the health dashboard treeview.
    STATUS_COLOURS = {
        'Good':     '#d4edda',  # soft green
        'Unstable': '#fff3cd',  # amber
        'Poor':     '#f8d7da',  # red-pink
        'Dead':     '#e2e3e5',  # grey
        'New':      '#cce5ff',  # blue
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

    def record_success(self, url, category, article_count):
        """Record a successful fetch (even if 0 articles fell within the time window)."""
        entry = self._get_or_create(url, category)
        entry['category']             = category
        entry['total_scans']         += 1
        entry['total_successes']     += 1
        entry['total_articles']      += article_count
        entry['consecutive_failures'] = 0
        entry['last_success']         = _now_str()
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

    # --- Querying ---

    def get_dead_feeds(self, threshold):
        """Return {url: entry} for feeds at or above the consecutive-failure threshold."""
        return {
            url: entry for url, entry in self.data.items()
            if entry.get('consecutive_failures', 0) >= threshold
        }

    def get_status(self, url):
        """Return a human-readable status label for a URL."""
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
                'last_success':         None,
                'last_error':           None,
                'last_error_msg':       None,
                'first_seen':           _now_str(),
            }
        return self.data[url]


# ---------------------------------------------------------------------------
# HELPER FUNCTIONS
# ---------------------------------------------------------------------------

def get_cutoff_time():
    """Return (cutoff_datetime, mode_label) based on the current day of week.

    On Mondays the lookback window is 72 hours to cover the weekend.
    All other days it is 24 hours.
    """
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

    Accepts feedparser time tuples, email-format strings, and common
    ISO / RFC date strings.  Returns None if the input cannot be parsed.
    """
    if not date_obj_or_str:
        return None

    if isinstance(date_obj_or_str, tuple):
        try:
            return datetime(*date_obj_or_str[:6], tzinfo=timezone.utc)
        except (ValueError, TypeError):
            pass

    date_str = str(date_obj_or_str).strip()

    try:
        parsed = email.utils.parsedate_to_datetime(date_str)
        if parsed:
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        pass

    for fmt in [
        '%d %b, %Y %z', '%d %b %Y %H:%M:%S %z', '%Y-%m-%d %H:%M:%S',
        '%a, %d %b %Y %H:%M:%S %Z', '%Y-%m-%dT%H:%M:%S%z', '%Y-%m-%dT%H:%M:%SZ',
    ]:
        try:
            dt = datetime.strptime(date_str, fmt)
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
    """Scan text for Indicators of Compromise (IOCs).

    IP addresses, CVEs, emails, and suspicious file extensions are flagged
    directly.  Hash patterns (MD5/SHA) are only flagged when IOC-related
    context words are also present, reducing false positives from random
    hex strings in article URLs and identifiers.

    Returns True if any IOC is detected, False otherwise.
    """
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


def fetch_feed_content(url):
    """Fetch raw feed bytes from a URL.

    Returns bytes on success, or b"ERROR: ..." for handled HTTP errors (403).
    Raises for all other network / HTTP errors.
    """
    ssl_context = ssl.create_default_context()
    headers = {'User-Agent': SEC_USER_AGENT} if "sec.gov" in url else STANDARD_HEADERS
    req = urllib.request.Request(url, headers=headers)

    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT_SECONDS, context=ssl_context) as response:
            content = response.read()

            if response.info().get('Content-Encoding') == 'gzip':
                try:
                    content = gzip.decompress(content)
                except gzip.BadGzipFile:
                    pass  # Header lied; content was not actually gzip — use as-is.
                except OSError as e:
                    raise RuntimeError(f"Gzip decompression failed: {e}") from e

            try:
                return content.decode('utf-8-sig').strip().encode('utf-8')
            except UnicodeDecodeError:
                return content.decode('iso-8859-1').encode('utf-8')

    except urllib.error.HTTPError as e:
        if e.code == 403:
            return b"ERROR: 403 Forbidden"
        raise


def process_single_feed(source_data, cutoff):
    """Fetch and parse one RSS/Atom feed, filtering entries newer than cutoff.

    Args:
        source_data: A (category, url) tuple from the source list.
        cutoff:      Timezone-aware datetime; only entries published after
                     this time are included.

    Returns:
        (category, findings_or_None, error_or_None)

        On success, findings always contains an 'article_count' key reflecting
        the raw number of recent entries before deduplication — used by the
        health DB to record meaningful yield numbers.
        On any failure, findings is None and error is a dict with 'url',
        'category', and 'error' keys.
    """
    category, url = source_data

    try:
        raw_xml = fetch_feed_content(url)

        if raw_xml.startswith(b"ERROR:"):
            return (category, None, {'url': url, 'category': category, 'error': raw_xml.decode()})

        feed = feedparser.parse(raw_xml)
        if feed.bozo and not feed.entries:
            return (category, None, {'url': url, 'category': category, 'error': "Invalid Feed Data"})

        site_title  = feed.feed.get('title', url[:30] + "...")
        site_buffer = []

        for entry in feed.entries:
            pub_date = None

            if hasattr(entry, 'published_parsed'):
                pub_date = parse_date_smart(entry.published_parsed)
            elif hasattr(entry, 'updated_parsed'):
                pub_date = parse_date_smart(entry.updated_parsed)

            if not pub_date:
                for cand in [entry.get('updated'), entry.get('pubDate'), entry.get('date')]:
                    if cand:
                        pub_date = parse_date_smart(cand)
                        if pub_date:
                            break

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

        # Always return a findings dict on success so we can record article_count = 0
        # for alive feeds that simply had no recent articles in the time window.
        findings = {
            'site_title':    site_title,
            'url':           url,
            'country':       get_country_from_url(url),
            'articles':      site_buffer,
            'article_count': len(site_buffer),
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

        self.btn_scan   = ttk.Button(control_frame, text="START SCAN",    command=self.start_scan_thread)
        self.btn_scan.pack(side=tk.LEFT, padx=5)

        self.btn_edit   = ttk.Button(control_frame, text="EDIT SOURCES",  command=self.open_source_editor)
        self.btn_edit.pack(side=tk.LEFT, padx=5)

        self.btn_health = ttk.Button(control_frame, text="FEED HEALTH",   command=self.open_feed_health_window)
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
    # FEED HEALTH DASHBOARD
    # ------------------------------------------------------------------

    def open_feed_health_window(self):
        """Open a sortable dashboard showing per-feed health statistics."""
        win = tk.Toplevel(self.root)
        win.title("Feed Health Dashboard")
        win.geometry("1100x600")
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
                f"  |  ✔ {counts.get('Good', 0)} Good"
                f"  ⚠ {counts.get('Unstable', 0)} Unstable"
                f"  ↓ {counts.get('Poor', 0)} Poor"
                f"  ✖ {counts.get('Dead', 0)} Dead"
                f"  ★ {counts.get('New', 0)} New"
            ),
            font=("Arial", 10),
        ).pack(side=tk.LEFT)

        ttk.Button(summary_frame, text="Manage Dead Feeds",
                   command=self.open_dead_feed_manager).pack(side=tk.RIGHT, padx=5)
        ttk.Button(summary_frame, text="↻ Refresh",
                   command=lambda: self._refresh_health_tree(tree)).pack(side=tk.RIGHT, padx=5)

        ttk.Separator(win, orient='horizontal').pack(fill=tk.X, padx=10)

        # --- Treeview ---
        cols = ('status', 'url', 'category', 'success_rate', 'avg_articles',
                'consec_fails', 'last_success', 'last_error')

        tree_frame = ttk.Frame(win)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=6)

        scroll_y = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL)
        scroll_x = ttk.Scrollbar(tree_frame, orient=tk.HORIZONTAL)

        tree = ttk.Treeview(
            tree_frame,
            columns=cols,
            show='headings',
            yscrollcommand=scroll_y.set,
            xscrollcommand=scroll_x.set,
            selectmode='browse',
        )
        scroll_y.config(command=tree.yview)
        scroll_x.config(command=tree.xview)
        scroll_y.pack(side=tk.RIGHT,  fill=tk.Y)
        scroll_x.pack(side=tk.BOTTOM, fill=tk.X)
        tree.pack(fill=tk.BOTH, expand=True)

        headings = {
            'status':       ('Status',         90, tk.CENTER),
            'url':          ('Feed URL',       340, tk.W),
            'category':     ('Category',       120, tk.W),
            'success_rate': ('Success Rate',    90, tk.CENTER),
            'avg_articles': ('Avg Articles',    90, tk.CENTER),
            'consec_fails': ('Consec. Fails',   90, tk.CENTER),
            'last_success': ('Last Success',   150, tk.CENTER),
            'last_error':   ('Last Error',     150, tk.CENTER),
        }
        for col, (label, width, anchor) in headings.items():
            tree.heading(col, text=label,
                         command=lambda c=col: self._sort_health_tree(tree, c, False))
            tree.column(col, width=width, anchor=anchor, minwidth=60)

        # Row background colours by status
        for status, bg in FeedHealthDB.STATUS_COLOURS.items():
            tree.tag_configure(status.lower(), background=bg)

        self._refresh_health_tree(tree)

        ttk.Label(win,
                  text="Click a column header to sort.  Double-click a row to copy the URL.",
                  font=("Arial", 8), foreground="gray").pack(pady=(0, 6))

        def on_double_click(event):
            item = tree.focus()
            if item:
                url_val = tree.item(item, 'values')[1]
                self.root.clipboard_clear()
                self.root.clipboard_append(url_val)
                self.root.update()
                win.title("Feed Health Dashboard  —  URL copied!")
                win.after(1800, lambda: win.title("Feed Health Dashboard"))

        tree.bind("<Double-1>", on_double_click)

    def _refresh_health_tree(self, tree):
        """Clear and repopulate the health treeview from the current DB."""
        for row in tree.get_children():
            tree.delete(row)
        for url, entry in self.health_db.data.items():
            status = self.health_db.get_status(url)
            tree.insert('', tk.END, values=(
                status,
                url,
                entry.get('category', '—'),
                self.health_db.get_success_rate_str(url),
                self.health_db.get_avg_articles_str(url),
                entry.get('consecutive_failures', 0),
                entry.get('last_success') or '—',
                entry.get('last_error')   or '—',
            ), tags=(status.lower(),))

    def _sort_health_tree(self, tree, col, reverse):
        """Sort the health treeview rows by the given column."""
        rows = [(tree.set(child, col), child) for child in tree.get_children('')]
        try:
            rows.sort(key=lambda x: float(x[0]) if x[0] not in ('—', '') else -1.0,
                      reverse=reverse)
        except ValueError:
            rows.sort(key=lambda x: x[0].lower(), reverse=reverse)
        for index, (_, child) in enumerate(rows):
            tree.move(child, '', index)
        tree.heading(col, command=lambda: self._sort_health_tree(tree, col, not reverse))

    # ------------------------------------------------------------------
    # DEAD FEED MANAGER
    # ------------------------------------------------------------------

    def open_dead_feed_manager(self, auto_prompt=False):
        """Open a dialog listing dead feeds with checkboxes to remove them.

        Args:
            auto_prompt: When True (called automatically after a scan), a more
                         prominent title is shown.  When False (opened from the
                         menu/button), an info dialog is shown if no dead feeds
                         exist yet.
        """
        dead = self.health_db.get_dead_feeds(DEAD_FEED_THRESHOLD)

        # Only show feeds that are still present in valid_sources.txt.
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

        title = ("⚠  Dead Feeds Detected After Scan" if auto_prompt
                 else "Dead Feed Manager")

        win = tk.Toplevel(self.root)
        win.title(title)
        win.geometry("840x520")
        win.resizable(True, True)
        win.grab_set()

        # --- Header ---
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

        # --- Scrollable checklist ---
        container = ttk.Frame(win)
        container.pack(fill=tk.BOTH, expand=True, padx=10)

        canvas      = tk.Canvas(container, borderwidth=0, background="#f9f9f9")
        vscroll     = ttk.Scrollbar(container, orient=tk.VERTICAL, command=canvas.yview)
        inner       = ttk.Frame(canvas, padding="4")
        inner.bind("<Configure>",
                   lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=inner, anchor='nw')
        canvas.configure(yscrollcommand=vscroll.set)
        vscroll.pack(side=tk.RIGHT, fill=tk.Y)
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Column labels
        col_hdr = ttk.Frame(inner)
        col_hdr.pack(fill=tk.X, pady=(0, 3))
        ttk.Label(col_hdr, text="Remove", width=7,  font=("Arial", 9, "bold")).pack(side=tk.LEFT)
        ttk.Label(col_hdr, text="Feed URL",         font=("Arial", 9, "bold"), width=52).pack(side=tk.LEFT)
        ttk.Label(col_hdr, text="Fails", width=6,  font=("Arial", 9, "bold")).pack(side=tk.LEFT)
        ttk.Label(col_hdr, text="Last Error",       font=("Arial", 9, "bold")).pack(side=tk.LEFT)
        ttk.Separator(inner, orient='horizontal').pack(fill=tk.X, pady=2)

        check_vars = {}

        # Sort by most failures first so the worst offenders are at the top.
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
            # Hovering shows the full URL in the window title bar.
            lbl.bind("<Enter>", lambda e, u=url: win.title(u))
            lbl.bind("<Leave>", lambda e: win.title(title))

            cf = entry.get('consecutive_failures', 0)
            ttk.Label(row, text=str(cf), width=6,
                      font=("Arial", 9, "bold"), foreground="#c0392b").pack(side=tk.LEFT)

            err_short = (entry.get('last_error_msg') or '—')[:65]
            ttk.Label(row, text=err_short,
                      font=("Arial", 9), foreground="gray").pack(side=tk.LEFT, padx=(4, 0))

            ttk.Separator(inner, orient='horizontal').pack(fill=tk.X)

        # --- Action buttons ---
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
                summary += (f"\n\n{len(not_found)} URL(s) were not found in the file "
                            f"(possibly already removed).")
            messagebox.showinfo("Done", summary, parent=win)
            win.destroy()

        ttk.Button(btn_frame, text="Select All",   command=select_all).pack(side=tk.LEFT, padx=4)
        ttk.Button(btn_frame, text="Deselect All", command=deselect_all).pack(side=tk.LEFT, padx=4)
        ttk.Button(btn_frame, text="Remove Selected",
                   command=remove_selected).pack(side=tk.RIGHT, padx=4)
        ttk.Button(btn_frame, text="Keep All / Close",
                   command=win.destroy).pack(side=tk.RIGHT, padx=4)

    def _remove_urls_from_sources(self, urls_to_remove):
        """Remove specific URLs from valid_sources.txt.

        Reads the file line-by-line and writes back every line whose stripped
        content is NOT in urls_to_remove.

        Returns:
            (removed_list, not_found_list)
        """
        remove_set = set(urls_to_remove)
        removed    = []
        not_found  = list(remove_set)
        new_lines  = []

        try:
            with open(SOURCE_FILE, 'r', encoding='utf-8') as fh:
                for line in fh:
                    stripped = line.strip()
                    if stripped in remove_set:
                        removed.append(stripped)
                        not_found = [u for u in not_found if u != stripped]
                    else:
                        new_lines.append(line)

            with open(SOURCE_FILE, 'w', encoding='utf-8') as fh:
                fh.writelines(new_lines)

        except OSError as e:
            messagebox.showerror("File Error", f"Could not modify {SOURCE_FILE}:\n{e}")
            return [], urls_to_remove

        return removed, not_found

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
            # Sync with OS clipboard before returning to prevent segfault on some platforms.
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

        Called repeatedly by Tkinter's event loop via root.after().
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
                    self.lbl_status.config(text="Scan Complete!")
                    self.btn_scan.config(state='normal')
                    self.btn_edit.config(state='normal')

                elif msg_type == "dead_feeds":
                    # Buttons are already re-enabled by the preceding "done"
                    # message, so this opens as a non-blocking prompt.
                    self.open_dead_feed_manager(auto_prompt=True)

        except queue.Empty:
            pass

        self.root.after(100, self.process_queue)

    # ------------------------------------------------------------------
    # SCAN THREAD
    # ------------------------------------------------------------------

    def start_scan_thread(self):
        """Disable buttons, clear the log, and launch the scan in a background thread."""
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
        """Main scan logic — runs entirely in a background thread.

        Loads sources, fans out feed fetches via a thread pool, records health
        stats for every feed, deduplicates results, writes the report file, then
        signals the main thread to re-enable controls.  If any feeds are now
        flagged as dead, it additionally triggers the dead feed manager dialog.
        """
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

        # Calculate the cutoff ONCE so every worker uses the exact same window.
        cutoff, mode = get_cutoff_time()
        self.log(f"--- Mode: {mode} ---", "INFO")

        category_findings    = {}
        dead_sites           = []
        priority_findings    = []
        processed_count      = 0
        total_findings_count = 0
        seen_links           = set()

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

                # --- Record health outcome for this feed ---
                if error_data:
                    dead_sites.append(error_data)
                    self.health_db.record_failure(
                        orig_url, orig_cat,
                        error_data.get('error', 'Unknown error'),
                    )
                else:
                    article_count = found_data.get('article_count', 0) if found_data else 0
                    self.health_db.record_success(orig_url, orig_cat, article_count)

                # --- Collect and deduplicate article findings ---
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

        # Save health DB once at the end (not per-feed) for efficiency.
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

                # Append a failed-feeds section to the report for reference.
                if dead_sites:
                    fh.write("\n### FAILED FEEDS THIS SCAN ###\n\n")
                    for d in dead_sites:
                        fh.write(f"URL: {d['url']}\nERROR: {d['error']}\n\n")

            self.log(f"\n--- Report Saved: {output_filename} ---", "SUCCESS")
            self.log(f"Total Unique Articles Found: {total_findings_count}", "INFO")

            if dead_sites:
                self.log(f"--- {len(dead_sites)} feed(s) failed this scan ---", "ERROR")

            # Log a one-line health summary.
            dead_count = len(self.health_db.get_dead_feeds(DEAD_FEED_THRESHOLD))
            self.log(
                f"--- Feed Health: {len(self.health_db.data)} tracked, "
                f"{dead_count} dead (>={DEAD_FEED_THRESHOLD} consecutive failures) ---",
                "INFO",
            )

        except OSError as e:
            self.log(f"Error writing file: {e}", "ERROR")

        # Signal "done" first so the buttons re-enable, THEN check for dead feeds.
        # process_queue handles "done" before "dead_feeds" because they're queued in order.
        self.scan_finished()

        # Check if any dead feeds are still present in the source file.
        try:
            if os.path.exists(SOURCE_FILE):
                with open(SOURCE_FILE, 'r', encoding='utf-8') as fh:
                    source_text = fh.read()
                dead_still_active = any(
                    url in source_text
                    for url in self.health_db.get_dead_feeds(DEAD_FEED_THRESHOLD)
                )
                if dead_still_active:
                    self.prompt_dead_feeds()
        except OSError:
            pass


# ---------------------------------------------------------------------------
# ENTRY POINT
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    root = tk.Tk()
    app  = OSINTApp(root)
    root.mainloop()
