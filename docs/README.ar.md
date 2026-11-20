<div dir="rtl">

# SafeScope بالعربي 🛡️

**SafeScope** أداة مفتوحة المصدر بتفحص إعدادات الأمان في أي موقع ويب بطريقة **آمنة وغير هجومية** — يعني بتعمل نفس الطلبات العادية اللي أي متصفح بيعملها، من غير أي هجمات أو payloads.

**جربها أونلاين:** <https://safescope-one.vercel.app>

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
pip install safescope-scanner
safescope scan example.com
safescope scan example.com -f html -o report.html
safescope scan a.com b.com --targets-file sites.txt   # كذا موقع مع بعض
safescope scan example.com -f sarif -o out.sarif      # لـ GitHub code scanning
safescope report scan.json -f html -o report.html     # تعرض scan محفوظ بشكل تاني
```

## الجديد في v0.2.0

- **حماية من DNS rebinding:** الموقع العام بيتصل بالـ IP اللي اتشيّك عليه بالظبط، فمحدش يقدر يغيّر رد الـ DNS بين التشييك والاتصال.
- **نتايج صادقة:** أي اختبار متعملش بيظهر `skipped`، ومبيظهرش كأنه نجح. وكل نتيجة ليها confidence.
- **حدود للموقع العام:** 25 ثانية للـ scan، و 4 scans في نفس الوقت، و 10 scans في الدقيقة لكل IP.
- **مزايا جديدة:** scan لكذا موقع، وتقرير SARIF، وأمر `report`.

## حدود الأداة

الدرجة الكويسة معناها إن الفحوصات السلبية نجحت، **مش دليل إن الموقع آمن**. SafeScope مش بديل عن اختبار الاختراق، ومبيدورش على ثغرات زي XSS أو SQL injection.

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
8. `src/safescope/netguard.py` — حماية الـ SSRF والـ DNS pinning.
9. `tests/` — كل جزء ليه tests بتشتغل من غير إنترنت.

ولفهم الصورة الكاملة: [architecture.md](architecture.md) و [security-model.md](security-model.md) و [checks.md](checks.md).

## ⚖️ استخدام مسؤول

افحص بس المواقع اللي بتملكها أو معاك إذن واضح بفحصها.

</div>
