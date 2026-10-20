// Hashly: Explorer shell extension. Adds a "VirusTotal" tab to the file Properties
// dialog and a "Scan with VirusTotal" right-click entry. Only the MD5 hash of the
// file is sent to VirusTotal; the file itself is never uploaded.
#define UNICODE
#define _UNICODE
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shellapi.h>
#include <olectl.h>
#include <shlobj.h>
#include <shlwapi.h>
#include <winhttp.h>
#include <bcrypt.h>
#include <commctrl.h>
#include <uxtheme.h>
#include <string>
#include <vector>
#include "resource.h"

// {7B3C5E52-4A1D-4C8E-9F26-5D1B8E0A6C31}
static const CLSID CLSID_Hashly =
    {0x7b3c5e52, 0x4a1d, 0x4c8e, {0x9f, 0x26, 0x5d, 0x1b, 0x8e, 0x0a, 0x6c, 0x31}};
static const wchar_t* kClsidStr = L"{7B3C5E52-4A1D-4C8E-9F26-5D1B8E0A6C31}";
static const wchar_t* kTabTitle = L"VirusTotal";
static const UINT WM_SCAN_DONE = WM_APP + 1;

static HINSTANCE g_inst;
static LONG g_refs;

// ---------------------------------------------------------------- helpers

static std::wstring Widen(const std::string& s) {
    if (s.empty()) return L"";
    int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0);
    std::wstring w(n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), &w[0], n);
    return w;
}

static std::wstring KeyFilePath() {
    wchar_t dir[MAX_PATH];
    if (FAILED(SHGetFolderPathW(nullptr, CSIDL_APPDATA, nullptr, 0, dir))) return L"";
    return std::wstring(dir) + L"\\Hashly\\apikey.txt";
}

// API key: VT_API_KEY environment variable, else %APPDATA%\Hashly\apikey.txt
static std::wstring ReadApiKey() {
    wchar_t env[256];
    DWORD n = GetEnvironmentVariableW(L"VT_API_KEY", env, 256);
    std::wstring key = (n > 0 && n < 256) ? env : L"";
    if (key.empty()) {
        HANDLE f = CreateFileW(KeyFilePath().c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                               OPEN_EXISTING, 0, nullptr);
        if (f != INVALID_HANDLE_VALUE) {
            char buf[256]; DWORD got = 0;
            if (ReadFile(f, buf, sizeof(buf) - 1, &got, nullptr)) key = Widen(std::string(buf, got));
            CloseHandle(f);
        }
    }
    size_t b = key.find_first_not_of(L" \t\r\n\xFEFF");
    size_t e = key.find_last_not_of(L" \t\r\n");
    return b == std::wstring::npos ? L"" : key.substr(b, e - b + 1);
}

static bool Md5File(const std::wstring& path, std::wstring& out) {
    HANDLE f = CreateFileW(path.c_str(), GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                           OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (f == INVALID_HANDLE_VALUE) return false;
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_HASH_HANDLE h = nullptr;
    bool ok = false;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_MD5_ALGORITHM, nullptr, 0) == 0 &&
        BCryptCreateHash(alg, &h, nullptr, 0, nullptr, 0, 0) == 0) {
        std::vector<BYTE> buf(1 << 20);
        DWORD n = 0;
        BOOL r;
        ok = true;
        while ((r = ReadFile(f, buf.data(), (DWORD)buf.size(), &n, nullptr)) && n)
            if (BCryptHashData(h, buf.data(), n, 0) != 0) { ok = false; break; }
        BYTE d[16];
        if (!r || !ok || BCryptFinishHash(h, d, sizeof(d), 0) != 0) ok = false;
        else {
            wchar_t hex[33];
            for (int i = 0; i < 16; i++) swprintf_s(hex + i * 2, 3, L"%02x", d[i]);
            out = hex;
        }
    }
    if (h) BCryptDestroyHash(h);
    if (alg) BCryptCloseAlgorithmProvider(alg, 0);
    CloseHandle(f);
    return ok;
}

// ---------------------------------------------------------------- VirusTotal

struct WinHttpHandle {
    HINTERNET h;
    explicit WinHttpHandle(HINTERNET x) : h(x) {}
    ~WinHttpHandle() { if (h) WinHttpCloseHandle(h); }
};

// Returns the HTTP status, or 0 on transport failure.
static int VtLookup(const std::wstring& md5, const std::wstring& key, std::string& body) {
    WinHttpHandle ses(WinHttpOpen(L"Hashly/1.0", WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                                  WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0));
    if (!ses.h) return 0;
    WinHttpHandle con(WinHttpConnect(ses.h, L"www.virustotal.com", INTERNET_DEFAULT_HTTPS_PORT, 0));
    if (!con.h) return 0;
    std::wstring path = L"/api/v3/files/" + md5;
    WinHttpHandle req(WinHttpOpenRequest(con.h, L"GET", path.c_str(), nullptr, WINHTTP_NO_REFERER,
                                         WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE));
    if (!req.h) return 0;
    std::wstring hdr = L"x-apikey: " + key;
    if (!WinHttpSendRequest(req.h, hdr.c_str(), (DWORD)-1, nullptr, 0, 0, 0) ||
        !WinHttpReceiveResponse(req.h, nullptr))
        return 0;
    DWORD status = 0, sz = sizeof(status);
    WinHttpQueryHeaders(req.h, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                        WINHTTP_HEADER_NAME_BY_INDEX, &status, &sz, WINHTTP_NO_HEADER_INDEX);
    DWORD avail = 0;
    while (WinHttpQueryDataAvailable(req.h, &avail) && avail) {
        size_t old = body.size();
        body.resize(old + avail);
        DWORD got = 0;
        if (!WinHttpReadData(req.h, &body[old], avail, &got)) break;
        body.resize(old + got);
    }
    return (int)status;
}

// Minimal JSON walker: just enough to pull fields out of the VirusTotal reply.
static size_t Ws(const std::string& s, size_t i) {
    while (i < s.size() && isspace((unsigned char)s[i])) i++;
    return i;
}
static size_t SkipStr(const std::string& s, size_t i) {  // i at opening quote
    for (i++; i < s.size() && s[i] != '"'; i++)
        if (s[i] == '\\') i++;
    return i + 1;
}
static size_t SkipValue(const std::string& s, size_t i) {
    i = Ws(s, i);
    if (i >= s.size()) return i;
    if (s[i] == '"') return SkipStr(s, i);
    if (s[i] == '{' || s[i] == '[') {
        int depth = 0;
        for (; i < s.size(); i++) {
            char c = s[i];
            if (c == '"') i = SkipStr(s, i) - 1;
            else if (c == '{' || c == '[') depth++;
            else if ((c == '}' || c == ']') && --depth == 0) return i + 1;
        }
        return i;
    }
    while (i < s.size() && !strchr(",}] \r\n\t", s[i])) i++;
    return i;
}
// Calls f(key, valueStart, valueEnd) for each member of the object at `obj`; f returns false to stop.
template <class F> static void EachMember(const std::string& s, size_t obj, F f) {
    size_t i = Ws(s, obj);
    if (i >= s.size() || s[i] != '{') return;
    for (i++;;) {
        i = Ws(s, i);
        if (i >= s.size() || s[i] != '"') return;
        size_t ke = SkipStr(s, i);
        std::string key = s.substr(i + 1, ke - i - 2);
        i = Ws(s, ke);
        if (i >= s.size() || s[i] != ':') return;
        i = Ws(s, i + 1);
        size_t ve = SkipValue(s, i);
        if (!f(key, i, ve)) return;
        i = Ws(s, ve);
        if (i < s.size() && s[i] == ',') i++; else return;
    }
}
static bool Member(const std::string& s, size_t obj, const char* key, size_t& pos) {
    bool found = false;
    EachMember(s, obj, [&](const std::string& k, size_t b, size_t) {
        if (k == key) { pos = b; found = true; return false; }
        return true;
    });
    return found;
}
static std::string StrAt(const std::string& s, size_t pos) {
    if (pos >= s.size() || s[pos] != '"') return "";
    std::string out;
    for (size_t i = pos + 1; i < s.size() && s[i] != '"'; i++) {
        if (s[i] == '\\' && i + 1 < s.size()) i++;
        out += s[i];
    }
    return out;
}
static long long NumAt(const std::string& s, size_t pos) { return pos < s.size() ? atoll(s.c_str() + pos) : 0; }
static long long NumMember(const std::string& s, size_t obj, const char* key) {
    size_t p; return Member(s, obj, key, p) ? NumAt(s, p) : 0;
}
static std::wstring StrMember(const std::string& s, size_t obj, const char* key) {
    size_t p; return Member(s, obj, key, p) ? Widen(StrAt(s, p)) : L"";
}

enum State { StError, StUnknown, StClean, StSuspicious, StMalicious };
struct Row { std::wstring engine, category, result; };
struct ScanResult {
    std::wstring verdict;   // headline
    std::wstring md5;
    std::wstring info;      // file name / type / size / date / md5 (success only)
    std::wstring details;   // longer message for error and unknown states
    State state = StError;
    long long mal = 0, sus = 0, harm = 0, und = 0;
    std::vector<Row> rows;  // flagged engines first
};

static std::wstring FormatUnixTime(long long t) {
    ULARGE_INTEGER u;
    u.QuadPart = (ULONGLONG)(t + 11644473600LL) * 10000000ULL;
    FILETIME ft = {u.LowPart, u.HighPart};
    SYSTEMTIME st;
    if (!FileTimeToSystemTime(&ft, &st)) return L"?";
    wchar_t buf[40];
    swprintf_s(buf, L"%04d-%02d-%02d %02d:%02d UTC", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute);
    return buf;
}

static void ParseReport(const std::string& body, const std::wstring& file, ScanResult& r) {
    size_t data, attrs, stats, results;
    if (!Member(body, 0, "data", data) || !Member(body, data, "attributes", attrs) ||
        !Member(body, attrs, "last_analysis_stats", stats)) {
        r.verdict = L"Unexpected reply from VirusTotal";
        return;
    }
    r.mal = NumMember(body, stats, "malicious");
    r.sus = NumMember(body, stats, "suspicious");
    r.harm = NumMember(body, stats, "harmless");
    r.und = NumMember(body, stats, "undetected");
    long long flagged = r.mal + r.sus, total = flagged + r.harm + r.und;
    wchar_t buf[256];
    if (flagged > 0) {
        swprintf_s(buf, L"%lld/%lld security vendors flagged this file as %s", flagged, total,
                   r.mal > 0 ? L"malicious" : L"suspicious");
        r.verdict = buf;
        r.state = r.mal > 0 ? StMalicious : StSuspicious;
    } else {
        r.verdict = L"No security vendors flagged this file as malicious";
        r.state = StClean;
    }

    std::wstring name = StrMember(body, attrs, "meaningful_name");
    if (name.empty()) name = file.substr(file.find_last_of(L'\\') + 1);
    std::wstring type = StrMember(body, attrs, "type_description");
    wchar_t size[32] = L"";
    StrFormatByteSizeW(NumMember(body, attrs, "size"), size, 32);
    long long when = NumMember(body, attrs, "last_analysis_date");
    r.info = name + L"\r\n" + type + L"  |  " + size + L"  |  analysed " + FormatUnixTime(when) +
             L"\r\nMD5 " + r.md5;

    if (Member(body, attrs, "last_analysis_results", results)) {
        std::vector<Row> flaggedRows, otherRows;
        EachMember(body, results, [&](const std::string& engine, size_t b, size_t) {
            size_t p;
            if (!Member(body, b, "category", p)) return true;
            Row row{Widen(engine), Widen(StrAt(body, p)), StrMember(body, b, "result")};
            bool hit = row.category == L"malicious" || row.category == L"suspicious";
            (hit ? flaggedRows : otherRows).push_back(row);
            return true;
        });
        r.rows = flaggedRows;
        r.rows.insert(r.rows.end(), otherRows.begin(), otherRows.end());
    }
}

static void RunScan(const std::wstring& file, ScanResult& r) {
    std::wstring key = ReadApiKey();
    if (key.empty()) {
        r.verdict = L"VirusTotal API key missing";
        r.details = L"Paste your API key into this file (one line) and click \"Check again\":\r\n\r\n" +
                    KeyFilePath() + L"\r\n\r\nAlternatively set the VT_API_KEY environment variable.\r\n"
                    L"Free keys: https://www.virustotal.com (profile > API key).";
        return;
    }
    if (!Md5File(file, r.md5)) {
        r.verdict = L"Could not read the file";
        return;
    }
    std::string body;
    int status = VtLookup(r.md5, key, body);
    switch (status) {
    case 200: ParseReport(body, file, r); break;
    case 404:
        r.state = StUnknown;
        r.info = r.md5.empty() ? L"" : L"MD5 " + r.md5;
        r.verdict = L"Unknown to VirusTotal";
        r.details = L"VirusTotal has never seen a file with this hash. The file was not uploaded.\r\n"
                    L"You can upload it manually via \"Open on VirusTotal\".";
        break;
    case 401: case 403: r.verdict = L"API key rejected by VirusTotal"; break;
    case 429: r.verdict = L"Rate limit reached (free keys: 4 requests/min). Try again shortly."; break;
    case 0:   r.verdict = L"Network error: could not reach virustotal.com"; break;
    default: {
        wchar_t buf[64]; swprintf_s(buf, L"VirusTotal returned HTTP %d", status); r.verdict = buf;
    }
    }
}

// ---------------------------------------------------------------- property page

struct PageCtx {
    std::wstring file, md5;
    ScanResult res;
    bool loading = true;
    HFONT head = nullptr, big = nullptr, normal = nullptr;
};

static COLORREF StateColor(State s) {
    switch (s) {
    case StMalicious:  return RGB(205, 32, 44);
    case StSuspicious: return RGB(214, 120, 0);
    case StClean:      return RGB(30, 140, 60);
    default:           return RGB(140, 140, 140);
    }
}
static COLORREF CategoryColor(const std::wstring& c) {
    if (c == L"malicious") return StateColor(StMalicious);
    if (c == L"suspicious") return StateColor(StSuspicious);
    if (c == L"harmless" || c == L"undetected") return StateColor(StClean);
    return StateColor(StError);
}
static const wchar_t* CategoryLabel(const std::wstring& c) {
    if (c == L"malicious") return L"Malicious";
    if (c == L"suspicious") return L"Suspicious";
    if (c == L"harmless") return L"Harmless";
    if (c == L"undetected") return L"Undetected";
    if (c == L"timeout" || c == L"confirmed-timeout") return L"Timed out";
    if (c == L"type-unsupported") return L"Not supported";
    if (c == L"failure") return L"Failure";
    return c.c_str();
}

// Score ring, like VirusTotal's: ring filled in proportion to detections, count in the middle.
static void DrawScore(const DRAWITEMSTRUCT* d, const PageCtx* ctx) {
    HDC dc = d->hDC;
    RECT rc = d->rcItem;
    DrawThemeParentBackground(d->hwndItem, dc, &rc);
    int w = rc.right - rc.left, h = rc.bottom - rc.top;
    int sz = min(w, h), pen = max(4, sz / 11);
    int cx = rc.left + w / 2, cy = rc.top + h / 2, r = sz / 2 - pen;

    const ScanResult& s = ctx->res;
    State st = ctx->loading ? StError : s.state;
    long long flagged = s.mal + s.sus, total = flagged + s.harm + s.und;
    double ratio = st == StClean ? 1.0 : (total > 0 ? (double)flagged / total : 0.0);
    if (flagged > 0 && ratio < 0.05) ratio = 0.05;  // keep a single hit visible

    SelectObject(dc, GetStockObject(NULL_BRUSH));
    HPEN base = CreatePen(PS_SOLID, pen, RGB(225, 225, 225));
    HGDIOBJ old = SelectObject(dc, base);
    Ellipse(dc, cx - r, cy - r, cx + r, cy + r);
    if (ratio > 0) {
        HPEN arc = CreatePen(PS_SOLID, pen, StateColor(st));
        SelectObject(dc, arc);
        if (ratio >= 0.999) Ellipse(dc, cx - r, cy - r, cx + r, cy + r);
        else {
            MoveToEx(dc, cx, cy - r, nullptr);
            AngleArc(dc, cx, cy, r, 90.0f, (FLOAT)(-360.0 * ratio));  // clockwise from 12 o'clock
        }
        SelectObject(dc, base);
        DeleteObject(arc);
    }
    SelectObject(dc, old);
    DeleteObject(base);

    wchar_t num[32], sub[32] = L"";
    if (ctx->loading) wcscpy_s(num, L"...");
    else if (st == StUnknown) wcscpy_s(num, L"?");
    else if (st == StError) wcscpy_s(num, L"!");
    else {
        swprintf_s(num, L"%lld", flagged);
        swprintf_s(sub, L"/ %lld", total);
    }
    SetBkMode(dc, TRANSPARENT);
    HGDIOBJ oldFont = SelectObject(dc, ctx->big);
    TEXTMETRICW tb, ts;
    GetTextMetricsW(dc, &tb);
    SelectObject(dc, ctx->normal);
    GetTextMetricsW(dc, &ts);
    int th = tb.tmHeight + (sub[0] ? ts.tmHeight : 0), top = cy - th / 2;
    RECT line = {rc.left, top, rc.right, top + tb.tmHeight};
    SelectObject(dc, ctx->big);
    SetTextColor(dc, StateColor(st));
    DrawTextW(dc, num, -1, &line, DT_CENTER | DT_SINGLELINE | DT_NOPREFIX);
    if (sub[0]) {
        line = {rc.left, top + tb.tmHeight, rc.right, top + th};
        SelectObject(dc, ctx->normal);
        SetTextColor(dc, RGB(120, 120, 120));
        DrawTextW(dc, sub, -1, &line, DT_CENTER | DT_SINGLELINE | DT_NOPREFIX);
    }
    SelectObject(dc, oldFont);
}

// Thin stacked bar: malicious / suspicious / clean shares of all engines.
static void DrawBar(const DRAWITEMSTRUCT* d, const PageCtx* ctx) {
    HDC dc = d->hDC;
    RECT rc = d->rcItem;
    DrawThemeParentBackground(d->hwndItem, dc, &rc);
    HBRUSH track = CreateSolidBrush(RGB(225, 225, 225));
    FillRect(dc, &rc, track);
    DeleteObject(track);
    const ScanResult& s = ctx->res;
    long long total = s.mal + s.sus + s.harm + s.und;
    if (ctx->loading || total <= 0) return;
    struct Seg { long long n; COLORREF c; } segs[] = {
        {s.mal, StateColor(StMalicious)}, {s.sus, StateColor(StSuspicious)}, {s.harm + s.und, StateColor(StClean)}};
    int width = rc.right - rc.left;
    long long done = 0;
    for (const Seg& g : segs) {
        if (g.n <= 0) continue;
        RECT seg = {rc.left + (int)(width * done / total), rc.top,
                    rc.left + (int)(width * (done + g.n) / total), rc.bottom};
        HBRUSH b = CreateSolidBrush(g.c);
        FillRect(dc, &seg, b);
        DeleteObject(b);
        done += g.n;
    }
}

static void FillList(HWND dlg, const ScanResult& r) {
    HWND list = GetDlgItem(dlg, IDC_LIST);
    SendMessageW(list, WM_SETREDRAW, FALSE, 0);
    ListView_DeleteAllItems(list);
    int i = 0;
    for (const Row& row : r.rows) {
        LVITEMW it = {};
        it.mask = LVIF_TEXT;
        it.iItem = i;
        it.pszText = const_cast<wchar_t*>(row.engine.c_str());
        ListView_InsertItem(list, &it);
        std::wstring verdict = std::wstring(L"\x25CF ") + CategoryLabel(row.category);
        ListView_SetItemText(list, i, 1, const_cast<wchar_t*>(verdict.c_str()));
        ListView_SetItemText(list, i, 2, const_cast<wchar_t*>(row.result.c_str()));
        i++;
    }
    SendMessageW(list, WM_SETREDRAW, TRUE, 0);
}

static void RedrawGraphics(HWND dlg) {
    InvalidateRect(GetDlgItem(dlg, IDC_SCORE), nullptr, FALSE);
    InvalidateRect(GetDlgItem(dlg, IDC_BAR), nullptr, FALSE);
}
struct Task { HWND dlg; std::wstring file; HMODULE mod; };

static DWORD WINAPI ScanThread(LPVOID p) {
    Task* t = (Task*)p;
    ScanResult* r = new ScanResult;
    RunScan(t->file, *r);
    if (!PostMessageW(t->dlg, WM_SCAN_DONE, 0, (LPARAM)r)) delete r;
    HMODULE mod = t->mod;
    delete t;
    FreeLibraryAndExitThread(mod, 0);  // keep the DLL mapped until this thread is done
}

static void StartScan(HWND dlg, PageCtx* ctx) {
    ctx->res = ScanResult();
    ctx->loading = true;
    SetDlgItemTextW(dlg, IDC_VERDICT, L"Checking VirusTotal...");
    SetDlgItemTextW(dlg, IDC_INFO, L"");
    SetDlgItemTextW(dlg, IDC_DETAILS, L"");
    ShowWindow(GetDlgItem(dlg, IDC_LIST), SW_SHOW);
    ShowWindow(GetDlgItem(dlg, IDC_DETAILS), SW_HIDE);
    ListView_DeleteAllItems(GetDlgItem(dlg, IDC_LIST));
    RedrawGraphics(dlg);
    EnableWindow(GetDlgItem(dlg, IDC_RESCAN), FALSE);
    Task* t = new Task{dlg, ctx->file, nullptr};
    GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCWSTR)&ScanThread, &t->mod);
    HANDLE th = CreateThread(nullptr, 0, ScanThread, t, 0, nullptr);
    if (th) { CloseHandle(th); return; }
    FreeLibrary(t->mod);
    delete t;
    SetDlgItemTextW(dlg, IDC_VERDICT, L"Could not start scan");
    EnableWindow(GetDlgItem(dlg, IDC_RESCAN), TRUE);
}

static INT_PTR CALLBACK PageProc(HWND dlg, UINT msg, WPARAM wp, LPARAM lp) {
    PageCtx* ctx = (PageCtx*)GetWindowLongPtrW(dlg, DWLP_USER);
    switch (msg) {
    case WM_INITDIALOG: {
        ctx = (PageCtx*)((PROPSHEETPAGEW*)lp)->lParam;
        SetWindowLongPtrW(dlg, DWLP_USER, (LONG_PTR)ctx);
        ctx->normal = (HFONT)SendDlgItemMessageW(dlg, IDC_VERDICT, WM_GETFONT, 0, 0);
        LOGFONTW lf;
        GetObjectW(ctx->normal, sizeof(lf), &lf);
        lf.lfWeight = FW_BOLD;
        LOGFONTW big = lf;
        lf.lfHeight = lf.lfHeight * 12 / 10;
        ctx->head = CreateFontIndirectW(&lf);
        big.lfHeight = big.lfHeight * 22 / 10;
        ctx->big = CreateFontIndirectW(&big);
        SendDlgItemMessageW(dlg, IDC_VERDICT, WM_SETFONT, (WPARAM)ctx->head, TRUE);

        HWND list = GetDlgItem(dlg, IDC_LIST);
        SetWindowTheme(list, L"Explorer", nullptr);
        ListView_SetExtendedListViewStyle(list, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER);
        RECT rc;
        GetClientRect(list, &rc);
        int w = rc.right - GetSystemMetrics(SM_CXVSCROLL);
        const wchar_t* titles[] = {L"Security vendor", L"Verdict", L"Detection"};
        int widths[] = {w * 36 / 100, w * 22 / 100, w - w * 36 / 100 - w * 22 / 100};
        for (int i = 0; i < 3; i++) {
            LVCOLUMNW col = {LVCF_TEXT | LVCF_WIDTH};
            col.pszText = const_cast<wchar_t*>(titles[i]);
            col.cx = widths[i];
            ListView_InsertColumn(list, i, &col);
        }
        StartScan(dlg, ctx);
        return TRUE;
    }
    case WM_SCAN_DONE: {
        ScanResult* r = (ScanResult*)lp;
        ctx->res = *r;
        ctx->loading = false;
        ctx->md5 = r->md5;
        delete r;
        const ScanResult& s = ctx->res;
        SetDlgItemTextW(dlg, IDC_VERDICT, s.verdict.c_str());
        SetDlgItemTextW(dlg, IDC_INFO, s.info.c_str());
        bool showList = !s.rows.empty();
        SetDlgItemTextW(dlg, IDC_DETAILS, s.details.c_str());
        ShowWindow(GetDlgItem(dlg, IDC_LIST), showList ? SW_SHOW : SW_HIDE);
        ShowWindow(GetDlgItem(dlg, IDC_DETAILS), showList || s.details.empty() ? SW_HIDE : SW_SHOW);
        FillList(dlg, s);
        RedrawGraphics(dlg);
        EnableWindow(GetDlgItem(dlg, IDC_RESCAN), TRUE);
        EnableWindow(GetDlgItem(dlg, IDC_OPENWEB), !s.md5.empty());
        return TRUE;
    }
    case WM_DRAWITEM: {
        const DRAWITEMSTRUCT* d = (const DRAWITEMSTRUCT*)lp;
        if (d->CtlID == IDC_SCORE) DrawScore(d, ctx);
        else if (d->CtlID == IDC_BAR) DrawBar(d, ctx);
        else return FALSE;
        return TRUE;
    }
    case WM_NOTIFY: {
        const NMHDR* h = (const NMHDR*)lp;
        if (h->idFrom != IDC_LIST || h->code != NM_CUSTOMDRAW) break;
        NMLVCUSTOMDRAW* cd = (NMLVCUSTOMDRAW*)lp;
        LRESULT res = CDRF_DODEFAULT;
        if (cd->nmcd.dwDrawStage == CDDS_PREPAINT) res = CDRF_NOTIFYITEMDRAW;
        else if (cd->nmcd.dwDrawStage == CDDS_ITEMPREPAINT) {
            size_t i = (size_t)cd->nmcd.dwItemSpec;
            if (i < ctx->res.rows.size()) cd->clrText = CategoryColor(ctx->res.rows[i].category);
            res = CDRF_NEWFONT;
        }
        SetWindowLongPtrW(dlg, DWLP_MSGRESULT, res);
        return TRUE;
    }
    case WM_COMMAND:
        switch (LOWORD(wp)) {
        case IDC_RESCAN: StartScan(dlg, ctx); return TRUE;
        case IDC_OPENWEB:
            ShellExecuteW(dlg, L"open", (L"https://www.virustotal.com/gui/file/" + ctx->md5).c_str(),
                          nullptr, nullptr, SW_SHOWNORMAL);
            return TRUE;
        case IDC_SETKEY: {
            std::wstring p = KeyFilePath();
            std::wstring dir = p.substr(0, p.rfind(L'\\'));
            CreateDirectoryW(dir.c_str(), nullptr);
            HANDLE f = CreateFileW(p.c_str(), GENERIC_WRITE, 0, nullptr, OPEN_ALWAYS, 0, nullptr);
            if (f != INVALID_HANDLE_VALUE) CloseHandle(f);  // create if missing, never truncate
            ShellExecuteW(dlg, L"open", L"notepad.exe", (L"\"" + p + L"\"").c_str(), nullptr, SW_SHOWNORMAL);
            return TRUE;
        }
        }
        break;
    case WM_DESTROY:
        if (ctx) {
            if (ctx->head) DeleteObject(ctx->head);
            if (ctx->big) DeleteObject(ctx->big);
            ctx->head = ctx->big = nullptr;
        }
        break;
    }
    return FALSE;
}

static UINT CALLBACK PageCallback(HWND, UINT msg, LPPROPSHEETPAGEW psp) {
    if (msg == PSPCB_RELEASE) delete (PageCtx*)psp->lParam;
    return 1;
}

// ---------------------------------------------------------------- COM object

class Hashly : public IShellExtInit, public IShellPropSheetExt, public IContextMenu {
    LONG ref_ = 1;
    std::wstring file_;
public:
    Hashly() { InterlockedIncrement(&g_refs); }
    ~Hashly() { InterlockedDecrement(&g_refs); }

    // IUnknown
    STDMETHODIMP QueryInterface(REFIID iid, void** pp) override {
        if (iid == IID_IUnknown || iid == IID_IShellExtInit) *pp = static_cast<IShellExtInit*>(this);
        else if (iid == IID_IShellPropSheetExt) *pp = static_cast<IShellPropSheetExt*>(this);
        else if (iid == IID_IContextMenu) *pp = static_cast<IContextMenu*>(this);
        else { *pp = nullptr; return E_NOINTERFACE; }
        AddRef();
        return S_OK;
    }
    STDMETHODIMP_(ULONG) AddRef() override { return InterlockedIncrement(&ref_); }
    STDMETHODIMP_(ULONG) Release() override {
        LONG n = InterlockedDecrement(&ref_);
        if (!n) delete this;
        return n;
    }

    // IShellExtInit: remember the first selected file (folders are ignored)
    STDMETHODIMP Initialize(PCIDLIST_ABSOLUTE, IDataObject* pdo, HKEY) override {
        if (!pdo) return E_INVALIDARG;
        FORMATETC fe = {CF_HDROP, nullptr, DVASPECT_CONTENT, -1, TYMED_HGLOBAL};
        STGMEDIUM sm = {};
        if (FAILED(pdo->GetData(&fe, &sm))) return E_FAIL;
        HRESULT hr = E_FAIL;
        wchar_t path[MAX_PATH];
        if (DragQueryFileW((HDROP)sm.hGlobal, 0, path, MAX_PATH)) {
            DWORD a = GetFileAttributesW(path);
            if (a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY)) {
                file_ = path;
                hr = S_OK;
            }
        }
        ReleaseStgMedium(&sm);
        return hr;
    }

    // IShellPropSheetExt
    STDMETHODIMP AddPages(LPFNSVADDPROPSHEETPAGE add, LPARAM lp) override {
        INITCOMMONCONTROLSEX icc = {sizeof(icc), ICC_LISTVIEW_CLASSES};
        InitCommonControlsEx(&icc);
        PageCtx* ctx = new PageCtx;
        ctx->file = file_;
        PROPSHEETPAGEW psp = {};
        psp.dwSize = sizeof(psp);
        psp.dwFlags = PSP_USEREFPARENT | PSP_USETITLE | PSP_USECALLBACK;
        psp.hInstance = g_inst;
        psp.pszTemplate = MAKEINTRESOURCEW(IDD_PAGE);
        psp.pszTitle = kTabTitle;
        psp.pfnDlgProc = PageProc;
        psp.pfnCallback = PageCallback;
        psp.pcRefParent = (UINT*)&g_refs;
        psp.lParam = (LPARAM)ctx;
        HPROPSHEETPAGE page = CreatePropertySheetPageW(&psp);
        if (!page) { delete ctx; return E_FAIL; }
        if (!add(page, lp)) DestroyPropertySheetPage(page);
        return S_OK;
    }
    STDMETHODIMP ReplacePage(UINT, LPFNSVADDPROPSHEETPAGE, LPARAM) override { return E_NOTIMPL; }

    // IContextMenu: one entry that opens the Properties dialog on the VirusTotal tab
    STDMETHODIMP QueryContextMenu(HMENU menu, UINT pos, UINT first, UINT, UINT flags) override {
        if (flags & CMF_DEFAULTONLY) return MAKE_HRESULT(SEVERITY_SUCCESS, 0, 0);
        InsertMenuW(menu, pos, MF_BYPOSITION | MF_STRING, first, L"Scan with VirusTotal");
        return MAKE_HRESULT(SEVERITY_SUCCESS, 0, 1);
    }
    STDMETHODIMP InvokeCommand(CMINVOKECOMMANDINFO* ci) override {
        if (!IS_INTRESOURCE(ci->lpVerb) || LOWORD(ci->lpVerb) != 0) return E_INVALIDARG;
        SHELLEXECUTEINFOW sei = {sizeof(sei)};
        sei.fMask = SEE_MASK_INVOKEIDLIST;
        sei.hwnd = ci->hwnd;
        sei.lpVerb = L"properties";
        sei.lpFile = file_.c_str();
        sei.lpParameters = kTabTitle;  // selects the tab with this title
        sei.nShow = SW_SHOW;
        return ShellExecuteExW(&sei) ? S_OK : E_FAIL;
    }
    STDMETHODIMP GetCommandString(UINT_PTR, UINT type, UINT*, CHAR* name, UINT cch) override {
        if (type == GCS_HELPTEXTW) { wcscpy_s((PWSTR)name, cch, L"Look this file up on VirusTotal"); return S_OK; }
        return E_NOTIMPL;
    }
};

class Factory : public IClassFactory {
    LONG ref_ = 1;
public:
    STDMETHODIMP QueryInterface(REFIID iid, void** pp) override {
        if (iid == IID_IUnknown || iid == IID_IClassFactory) { *pp = this; AddRef(); return S_OK; }
        *pp = nullptr;
        return E_NOINTERFACE;
    }
    STDMETHODIMP_(ULONG) AddRef() override { return InterlockedIncrement(&ref_); }
    STDMETHODIMP_(ULONG) Release() override {
        LONG n = InterlockedDecrement(&ref_);
        if (!n) delete this;
        return n;
    }
    STDMETHODIMP CreateInstance(IUnknown* outer, REFIID iid, void** pp) override {
        if (outer) return CLASS_E_NOAGGREGATION;
        Hashly* obj = new Hashly;
        HRESULT hr = obj->QueryInterface(iid, pp);
        obj->Release();
        return hr;
    }
    STDMETHODIMP LockServer(BOOL lock) override {
        if (lock) InterlockedIncrement(&g_refs); else InterlockedDecrement(&g_refs);
        return S_OK;
    }
};

// ---------------------------------------------------------------- DLL exports

BOOL WINAPI DllMain(HINSTANCE inst, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) { g_inst = inst; DisableThreadLibraryCalls(inst); }
    return TRUE;
}

STDAPI DllGetClassObject(REFCLSID clsid, REFIID iid, void** pp) {
    if (clsid != CLSID_Hashly) return CLASS_E_CLASSNOTAVAILABLE;
    Factory* f = new Factory;
    HRESULT hr = f->QueryInterface(iid, pp);
    f->Release();
    return hr;
}

STDAPI DllCanUnloadNow() { return g_refs == 0 ? S_OK : S_FALSE; }

static bool SetReg(const std::wstring& sub, const wchar_t* name, const std::wstring& value) {
    return RegSetKeyValueW(HKEY_CURRENT_USER, sub.c_str(), name, REG_SZ, value.c_str(),
                           (DWORD)((value.size() + 1) * sizeof(wchar_t))) == ERROR_SUCCESS;
}

// Per-user registration (HKCU): no admin rights needed.
STDAPI DllRegisterServer() {
    wchar_t dll[MAX_PATH];
    GetModuleFileNameW(g_inst, dll, MAX_PATH);
    std::wstring clsid = std::wstring(L"Software\\Classes\\CLSID\\") + kClsidStr;
    bool ok = SetReg(clsid, nullptr, L"Hashly VirusTotal") &&
              SetReg(clsid + L"\\InprocServer32", nullptr, dll) &&
              SetReg(clsid + L"\\InprocServer32", L"ThreadingModel", L"Apartment") &&
              SetReg(L"Software\\Classes\\*\\shellex\\PropertySheetHandlers\\Hashly", nullptr, kClsidStr) &&
              SetReg(L"Software\\Classes\\*\\shellex\\ContextMenuHandlers\\Hashly", nullptr, kClsidStr) &&
              SetReg(L"Software\\Microsoft\\Windows\\CurrentVersion\\Shell Extensions\\Approved",
                     kClsidStr, L"Hashly VirusTotal");
    SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, nullptr, nullptr);
    return ok ? S_OK : SELFREG_E_CLASS;
}

STDAPI DllUnregisterServer() {
    RegDeleteTreeW(HKEY_CURRENT_USER, (std::wstring(L"Software\\Classes\\CLSID\\") + kClsidStr).c_str());
    RegDeleteTreeW(HKEY_CURRENT_USER, L"Software\\Classes\\*\\shellex\\PropertySheetHandlers\\Hashly");
    RegDeleteTreeW(HKEY_CURRENT_USER, L"Software\\Classes\\*\\shellex\\ContextMenuHandlers\\Hashly");
    RegDeleteKeyValueW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Shell Extensions\\Approved", kClsidStr);
    SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, nullptr, nullptr);
    return S_OK;
}
