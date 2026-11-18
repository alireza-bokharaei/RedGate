# RedGate 2.1.0

**Governed Mission Workspace · فضای کاری مأموریت‌های امنیتیِ مجاز**

[فارسی](#fa) · [English](#en) · [Technical guide](redgate/README.md) · [Verification record](redgate/docs/VERIFICATION_2.1.0.md)

---

<a id="fa"></a>
<div dir="rtl">

## فارسی

RedGate سکویی برای **ارزیابی امنیتی مجاز و محدود، با تأیید انسانی و ثبت رویداد قابل‌بررسی** است. نسخهٔ **۲٫۱٫۰** مدیریت مأموریت، گراف دارایی و مسیر بررسی، شواهد HTTP و بازآزمایی محدود یافته‌ها را به معماری موجود اضافه می‌کند؛ بدون کنارگذاشتن محدودهٔ مجاز، بازهٔ **قواعد درگیری (RoE)**، سهمیه‌ها و تأیید دونفره.

> **فقط استفادهٔ مجاز:** پیش از هر بررسی، مجوز کتبی مالک دارایی و محدودهٔ فعال لازم است. دیدن داشبورد یا ذخیرهٔ برنامه، اسکن را شروع نمی‌کند. خروجی مدل و اسکریپت تولیدشده قابل‌اعتماد فرض نمی‌شوند. [سیاست امنیتی](redgate/SECURITY.md) و [محدودیت‌ها](redgate/LIMITATIONS.md) را بخوانید.

### قابلیت‌های نسخهٔ ۲٫۱

- **مأموریت ماندگار:** برنامه‌ریزی، شروع صریح، توقف موقت، ادامه و لغو، همراه با بودجهٔ اقدام، مهلت مطلق، checkpoint و گزارش Markdown/JSON. راه‌اندازی مجدد، کار را خودکار ادامه نمی‌دهد.
- **دو گراف:** موجودی دارایی‌های هر engagement و مسیر هدف ← اقدام ← بررسی ← یافته/شواهد/بازآزمایی. کشف دارایی به معنای آزمایش یا امن‌بودن آن نیست.
- **شواهد HTTP با Go:** درخواست ناشناس و محدود HEAD/GET، اتصال به IP تأییدشده با حفظ Host/SNI، بررسی گواهی TLS و عدم دنبال‌کردن redirect. پیش‌فرض HEAD و عدم ذخیرهٔ بدنه است؛ پیش‌نمایش متنی اختیاری حداکثر ۸ کیبی‌بایت و پالایش آن الگو‌محور است.
- **بازآزمایی محتاطانه:** فقط بررسی هدرهای امنیتیِ پشتیبانی‌شده در endpoint اصلی؛ نتیجه به تاریخچه اضافه می‌شود و نظر تحلیلگر یا مدرک قبلی تغییر نمی‌کند.
- **کنسول JavaScript:** گراف SVG با کنترل صفحه‌کلید، نمایش امن متن، چیدمان موبایل و کنارگذاشتن پاسخ‌های قدیمی پس از تغییر هویت یا engagement؛ بدون CDN یا سرور جداگانهٔ فرانت‌اند در زمان اجرا.
- **عملیات و بسته‌بندی:** ابزارهای Bash، وابستگی‌های قفل‌شده، پشتیبان‌گیری سازگار با SQLite WAL، چرخش کلید، Docker چندمرحله‌ای و گردش‌کار CI. قابلیت‌های قبلی Skills، حافظهٔ محدود به engagement، مدل محلی، اعتبارسنجی چهار زبان و زنجیرهٔ audit حفظ شده‌اند.

### فناوری‌ها

- **Python / FastAPI:** درگاه سیاست‌گذاری، API، احراز هویت، مأموریت‌ها و کنترل خروجی مدل.
- **Go:** جمع‌آورندهٔ بومی شواهد و runner محدودکنندهٔ فرایندها.
- **JavaScript / SVG:** رابط وب، گراف‌ها و ابزار اعتبارسنجی/تست.
- **Bash:** راه‌اندازی، اعتبارنامه‌ها، پشتیبان‌گیری و بررسی یکپارچه.
- **Docker Compose:** بسته‌بندی سرویس‌ها و تفکیک شبکه‌های کنترل، هدف و inference؛ پایگاه دادهٔ برنامه همچنان **SQLite** است.

### شروع سریع با Docker

پیش‌نیاز: Linux، Docker Engine، Compose نسخهٔ ۲٫۲۰ به بالا و BuildKit. پس از دریافت کد این نسخه، از ریشهٔ مخزن اجرا کنید:

<div dir="ltr">

```bash
cd redgate
./scripts/bootstrap_env.sh
./scripts/redgate.sh doctor
./scripts/redgate.sh up --full
```

</div>

Bootstrap توکن‌های خصوصی اپراتورها را فقط یک‌بار نمایش می‌دهد؛ آن‌ها را امن نگه دارید. در **http://127.0.0.1:8000** با دکمهٔ **Token** وارد شوید؛ مستندات API در `/docs` است. Compose ورود demo را خاموش می‌کند و فقط پورت درگاه را روی loopback منتشر می‌کند. برای دسترسی راه دور، TLS و کنترل دسترسی شبکه لازم است.

<div dir="ltr">

```bash
./scripts/redgate.sh up --lite
./scripts/redgate.sh status
./scripts/redgate.sh backup
./scripts/redgate.sh down
```

</div>

- **full:** تعریف image شامل ابزارهای اعتبارسنجی و اجرای هر چهار زبان است.
- **lite:** ابزارهای Go/Node برای اسکریپت‌ها را حذف می‌کند، نه کنترل‌های سیاست یا جمع‌آوری بومی شواهد را؛ Skillهای وابسته به Go/JS کامل اجرا نمی‌شوند.
- **evidence:** هدف ساخت جداگانهٔ runner است که اجرای اسکریپت را رد می‌کند؛ یک flavor کامل Compose نیست.
- فرمان `down` داده‌های named volume را نگه می‌دارد؛ برای ارتقا از `down --volumes` استفاده نکنید.

**وضعیت Docker:** daemon محلی در دسترس نبود؛ اما [بررسی GitHub برای commit `763da11`](https://github.com/alireza-bokharaei/RedGate/actions/runs/44288999257) موفق شد: ساخت و راه‌اندازی `full` و `lite`، بررسی readiness و قابلیت‌های نصب‌شده، و ساخت هدف `evidence`. این بررسی کنترل‌شده جای تأیید محیط تولید، جداسازی کد متخاصم یا سنجش منابع را نمی‌گیرد. **هیچ کاهش اندازه یا افزایش سرعتِ اندازه‌گیری‌شده‌ای ادعا نمی‌شود.** [راهنمای استقرار و ارتقا](redgate/docs/DEPLOYMENT.md).

### توسعه و بررسی محلی

برای بررسی کامل به Python ۳٫۱۱ به بالا، Go ۱٫۲۲ به بالا، Node ۲۲٫۱۳ به بالا و ShellCheck نیاز دارید. از ریشهٔ مخزن:

<div dir="ltr">

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --require-hashes -r redgate/requirements-dev.txt
cd redgate
npm ci --ignore-scripts
./scripts/verify.sh
./scripts/start_local.sh
```

</div>

راه‌انداز محلی به‌طور پیش‌فرض loopback، مدل mock و اعتبارنامهٔ موقت خصوصی دارد؛ `.env` را خودکار به shell وارد نمی‌کند. اجرای مستقیم روی میزبان، مرز جداسازی کد متخاصم نیست. حالت `REDGATE_DEMO_MODE=true` فقط برای آزمایشگاه خصوصی است؛ هر فردی که به آن gateway دسترسی داشته باشد می‌تواند هویت آزمایشی بگیرد.

### مدل محلی

پیش‌فرض **mock** است؛ مدل یا درخواست خارجی لازم ندارد. برای نوشتن تنظیمات اولیهٔ Ollama در Compose، بدون دریافت وزن مدل:

<div dir="ltr">

```bash
./scripts/setup_local_llm.sh --compose ollama
```

</div>

دریافت مدل فقط با `--pull` صریح انجام می‌شود و ممکن است چندین گیگابایت باشد. تنظیمات runtime ذخیره‌شده در SQLite بر پیش‌فرض‌های `.env` اولویت دارند؛ برای پایگاه دادهٔ موجود، بخش مدیریتی **Local AI → Runtime** را به‌روز کنید. آدرس loopback میزبان از داخل کانتینر قابل‌جایگزینی با سرویس Ollama نیست؛ راهنمای فنی، تنظیمات شبکهٔ میزبان و کانتینر را جدا توضیح می‌دهد.

### ایمنی، ظرفیت و وضعیت بررسی

- هر مأموریت: **۱ تا ۸ میزبان، ۱ تا ۶۴ اقدام و ۱۰ تا ۱۸۰۰ ثانیه**؛ هم‌زمان حداکثر **دو مأموریت در سامانه و یک مأموریت برای هر مالک**.
- توقف موقت زمان را تمدید نمی‌کند و اقدام ناموفق/رزروشده برگشت داده نمی‌شود. لغو نمی‌تواند درخواست قبلاً ارسال‌شده را پس بگیرد؛ اجرای شبکه تضمین exactly-once ندارد.
- checksum، نمای **ذخیره‌شده و پالایش‌شده** را کنترل می‌کند، نه اصالت بستهٔ خام شبکه. پالایش تضمین حذف همهٔ اسرار یا اطلاعات شخصی نیست؛ `not_observed` نیز به معنای رفع قطعی مشکل نیست.
- runner یک VM یا sandbox کامل سیستم‌عامل نیست و firewall نصب نمی‌کند. پیش از اجرای کد نامطمئن، جداسازی مناسب و سیاست خروجی مستقلِ default-deny برای IPv4 و IPv6 لازم است.
- بررسی محلی ثبت‌شده در **۲۰۲۶-۱۱-۱۸**: **۱۰۸ تست Python و ۹ تست JavaScript موفق**، به‌علاوهٔ Go race/vet، ShellCheck و جریان واقعی مرورگر Chromium. یک هشدار منسوخ‌شدن backend در TestClient ثبت شده است. وضعیت جاری CI را برای همان commit در تب Actions ببینید؛ وجود workflow به معنای عبور آن نیست.

### نسبت با ARTEX و مجوز

این نسخه، **پیاده‌سازی مستقل قابلیت‌های منتخبِ الهام‌گرفته از ARTEX است؛ نه ادغام کامل پروژه**. هیچ سورس، دارایی یا dependency از ARTEX وارد نشده است. RedGate مجوز **MIT** موجود را برای کد خود حفظ می‌کند؛ ARTEX مرجع تحت **AGPL-3.0** است. ادغام کامل سورس هنوز انجام نشده و به تصمیم صریح دربارهٔ سازگاری مجوز و دامنهٔ امنیتی نیاز دارد. مجوز وابستگی‌ها و ابزارهای ثالث مستقل باقی می‌ماند.

**مستندات:** [یادداشت نسخه به فارسی](redgate/docs/RELEASE_2.1.0_FA.md) · [محدوده و منشأ](redgate/docs/ARTEX_SCOPE.md) · [گزارش بررسی](redgate/docs/VERIFICATION_2.1.0.md) · [معماری](redgate/docs/ARCHITECTURE.md) · [راهنمای فنی](redgate/README.md) · [MIT](redgate/LICENSE)

</div>

---

<a id="en"></a>

## English

RedGate is a **policy-controlled platform for authorized, bounded security assessment with human review and an auditable execution trail**. Version **2.1.0** adds missions, asset/exploration graphs, HTTP evidence and conservative finding retests without bypassing existing engagement scope, Rules of Engagement (RoE), quotas or two-person approvals.

> **Authorized use only:** obtain written asset-owner authorization and an active RoE window before testing. Viewing the dashboard or saving a plan never starts a scan. Models and generated scripts are untrusted. Read [Security](redgate/SECURITY.md) and [Limitations](redgate/LIMITATIONS.md).

### What's new in 2.1

- **Durable missions:** plan, explicitly start/pause/resume/cancel, enforce finite action/deadline budgets, preserve checkpoints and export Markdown/JSON. Restart never automatically resumes target contact.
- **Two graphs:** engagement asset inventory and a goal → intent → check → finding/evidence/retest trail. Discovery is not tested coverage or proof of security.
- **Go HTTP evidence:** bounded anonymous HEAD/GET, a pinned network dial retaining Host/TLS SNI, certificate verification and no redirects. HEAD/no body is the default; optional text previews are capped at 8 KiB and heuristically redacted.
- **Conservative retests:** repeat supported missing-security-header checks against their original endpoint. Append observations; never overwrite the analyst verdict or original evidence.
- **JavaScript console:** keyboard-operable SVG graphs, safe text rendering, mobile layout and stale-response guards across identity/engagement changes. No runtime CDN or separate frontend server.
- **Operations and packaging:** Bash helpers, locked dependencies, WAL-consistent SQLite backups, key rotation, multi-stage Docker targets and a CI workflow. Existing Skills, engagement-scoped memory, local-model support, four-language validation and hash-chained audit records remain.

### Technology

- **Python / FastAPI:** governance gateway, API, authentication, missions and model-output checks.
- **Go:** native HTTP evidence collector and bounded process runner.
- **JavaScript / SVG:** web console, graphs and validation/test tooling.
- **Bash:** lifecycle, credentials, backups and unified verification.
- **Docker Compose:** service packaging and separate control, target-egress and inference networks. The application database remains **SQLite**.

### Quickstart with Docker

Requires Linux, Docker Engine, Compose v2.20+ and BuildKit. After obtaining this version's source, run from the repository root:

```bash
cd redgate
./scripts/bootstrap_env.sh
./scripts/redgate.sh doctor
./scripts/redgate.sh up --full
```

Bootstrap prints private operator tokens once; save them securely. Open **http://127.0.0.1:8000**, press **Token**, and sign in. API documentation is at `/docs`. Compose disables demo login and publishes only the gateway on loopback. Remote access requires TLS and network access control.

```bash
./scripts/redgate.sh up --lite
./scripts/redgate.sh status
./scripts/redgate.sh backup
./scripts/redgate.sh down
```

- **full:** image definitions retain all four script validation/execution toolchains.
- **lite:** omits Go/Node script toolchains, not policy checks or native evidence; Skills depending on Go/JS cannot complete those adapter steps.
- **evidence:** a separate runner build target that rejects scripts, not a complete Compose flavor.
- `down` retains named-volume data. Never use `down --volumes` for an upgrade.

**Docker status:** no local daemon was available, but [GitHub verification of commit `763da11`](https://github.com/alireza-bokharaei/RedGate/actions/runs/44288999257) passed: `full`/`lite` image builds and startup, readiness/installed-capability checks, and the `evidence` target build. This controlled check does not replace intended-host validation, hostile-code containment or resource measurements. **No measured image-size reduction or speed improvement is claimed.** See [deployment and upgrades](redgate/docs/DEPLOYMENT.md).

### Local development and checks

The complete checks require Python 3.11+, Go 1.22+, Node 22.13+ and ShellCheck. From the repository root:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --require-hashes -r redgate/requirements-dev.txt
cd redgate
npm ci --ignore-scripts
./scripts/verify.sh
./scripts/start_local.sh
```

The local launcher defaults to loopback, mock AI and temporary private credentials; it does not automatically source `.env`. Direct host execution is not hostile-code isolation. `REDGATE_DEMO_MODE=true` is for an explicit private lab only: anyone reaching that gateway can obtain a lab identity.

### Local inference

Default **mock** mode needs no model or external AI call. Configure initial container-reachable Ollama settings without downloading weights:

```bash
./scripts/setup_local_llm.sh --compose ollama
```

Only explicit `--pull` downloads models, potentially many GB. Saved SQLite runtime settings take precedence over initial `.env` defaults; update **Local AI → Runtime** as an assigned admin for an existing database. A host loopback URL is not the container's Ollama service. The technical guide explains host and container networking separately.

### Safety, capacity and verification

- Per mission: **1–8 hosts, 1–64 actions and 10–1800 seconds**. At most **two active missions globally and one per owner**.
- Pausing does not extend the deadline; failed/reserved actions are not refunded. Cancellation cannot retract sent traffic. Exactly-once network execution is not guaranteed.
- Checksums cover the **stored, redacted representation**, not raw-wire authenticity. Redaction cannot guarantee removal of all secrets/PII, and `not_observed` does not prove a vulnerability is fixed.
- The runner is not a VM/full OS sandbox and does not install a firewall. Untrusted adapters require independently enforced hostile-code containment and default-deny IPv4/IPv6 egress.
- Recorded local verification on **2026-11-18**: **108 Python tests and 9 JavaScript tests passed**, plus Go race/vet, ShellCheck and a real Chromium workflow. One upstream TestClient-backend deprecation warning was recorded. Check Actions for the exact commit's current CI result; a workflow file is not itself a passing CI run.

### ARTEX scope and license

This is an **independent implementation of selected ARTEX-inspired workflows, not a whole-project merge**. No ARTEX source, assets or dependencies have been imported. RedGate retains its existing **MIT** license for its own code; the reviewed ARTEX reference uses **AGPL-3.0**. Whole-source integration remains unimplemented and requires an explicit license-compatibility and security-scope decision. Third-party tools/dependencies retain their respective licenses.

**Documentation:** [Technical guide and API](redgate/README.md) · [Architecture](redgate/docs/ARCHITECTURE.md) · [Deployment, backup and upgrade](redgate/docs/DEPLOYMENT.md) · [ARTEX scope/provenance](redgate/docs/ARTEX_SCOPE.md) · [Verification record](redgate/docs/VERIFICATION_2.1.0.md) · [Persian release notes](redgate/docs/RELEASE_2.1.0_FA.md) · [MIT license](redgate/LICENSE)
