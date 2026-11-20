<div dir="rtl">

# SafeScope بالعربي 🛡️

**SafeScope** أداة مفتوحة المصدر بتفحص إعدادات الأمان في أي موقع ويب بطريقة **آمنة وغير هجومية** — يعني بتعمل نفس الطلبات العادية اللي أي متصفح بيعملها، من غير أي هجمات أو payloads.

## بتفحص إيه؟

| الفحص | بيشوف إيه |
|---|---|
| `transport` | الموقع شغال على HTTPS؟ HTTP بيتحول لـ HTTPS؟ فيه HSTS؟ |
| `tls` | الشهادة موثوقة؟ هتنتهي إمتى؟ السيرفر لسه بيقبل TLS 1.0/1.1 القديمة؟ |
| `headers` | Security Headers زي CSP و X-Frame-Options و Referrer-Policy |
| `cookies` | الكوكيز عليها Secure و HttpOnly و SameSite؟ |
| `disclosure` | السيرفر بيكشف إصدارات البرامج؟ CORS مفتوح؟ فيه security.txt؟ |

وفي الآخر بيديك **درجة من 100** وتقييم من **A+ لـ F**، وكل مشكلة معاها شرح وطريقة الحل.

## التشغيل

```bash
pip install git+https://github.com/Karim-Bazooka/SafeScope.git
safescope scan example.com
safescope scan example.com -f html -o report.html
```

## جربه على جهازك من غير ما تفحص موقع حد

```bash
python examples/vulnerable_demo_server.py
safescope scan http://127.0.0.1:8000 --skip tls
```

## خريطة الكود (اقرأ بالترتيب ده)

1. `src/safescope/models.py` — شكل البيانات: Finding و Severity و ScanResult.
2. `src/safescope/http.py` — HTTP client صغير بيتابع الـ redirects.
3. `src/safescope/context.py` — بيخزن الردود عشان كل URL يتطلب مرة واحدة بس.
4. `src/safescope/checks/headers.py` — أسهل check تبدأ بيه.
5. باقي الـ checks، وبعدين `scanner.py` و `scoring.py`.
6. `src/safescope/reporters/` — إزاي النتيجة بتتحول لـ console / JSON / HTML.
7. `src/safescope/cli.py` — الأوامر اللي بتكتبها في الترمينال.
8. `tests/` — كل جزء ليه tests بتشتغل من غير إنترنت.

## ⚖️ استخدام مسؤول

افحص بس المواقع اللي بتملكها أو معاك إذن واضح بفحصها.

</div>
