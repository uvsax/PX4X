# 📊 PX4X — متعدد المستخدمين

موقع عربي (RTL) لإدارة ملفات الباوربوينت **بحسابات مستخدمين** — كل شخص يسجّل دخول
وملفاته خاصة بيه.

## المميزات
- 👤 **حسابات**: تسجيل حساب جديد / تسجيل دخول (كلمات المرور مشفّرة)
- ➕ رفع ملفات PPT / PPTX / PDF / ODP (حتى 200MB) — بالسحب أو بالضغط
- 👁 عرض الملف داخل الموقع (عارض Microsoft المدمج)
- 🔗 **روابط مشاركة عامة**: شارك أي ملف برابط يفتح بدون تسجيل دخول
- ⬇ تحميل و 🗑 حذف الملفات
- 🔒 عزل كامل: كل مستخدم يشوف ملفاته فقط

## 🔑 تفعيل "تسجيل الدخول بـ Google" (اختياري)

زر Google يظهر تلقائياً عند ضبط متغيري البيئة. الخطوات:

1. روح [Google Cloud Console](https://console.cloud.google.com/) وأنشئ مشروعاً جديداً
2. **APIs & Services → OAuth consent screen**: اختر External، املأ الاسم والبريد، واحفظ
3. **APIs & Services → Credentials → Create Credentials → OAuth client ID**:
   - نوع التطبيق: **Web application**
   - **Authorized redirect URIs**: أضف `https://YOUR-SERVICE.onrender.com/auth/google/callback`
     (استبدل YOUR-SERVICE برابط موقعك على Render)
4. انسخ **Client ID** و **Client Secret**
5. في Render: افتح خدمتك → **Environment** → أضف:
   - `GOOGLE_CLIENT_ID` = القيمة المنسوخة
   - `GOOGLE_CLIENT_SECRET` = القيمة المنسوخة
6. احفظ — Render يعيد النشر تلقائياً ويظهر زر Google بصفحة الدخول

## ملاحظات النشر
- **المعاينة** تحتاج رابطاً عاماً — تعمل على Render، وعلى التشغيل المحلي قد لا تظهر.
- على خطة Render **المجانية**: الملفات المرفوعة وقاعدة بيانات المستخدمين تُفقد عند
  إعادة تشغيل الخدمة (لا يوجد تخزين دائم). للحفظ الدائم استخدم قرصاً دائماً
  (Persistent Disk) أو قاعدة بيانات خارجية.

## التشغيل محلياً
```bash
pip install -r requirements.txt
uvicorn app:app --host 0.0.0.0 --port 8000
```

## النشر على Render
1. ارفع المشروع على GitHub (مجلد `static` **داخل** الريبو، مو الملفات بالجذر)
2. New → Web Service → اختر الريبو
3. Build Command: `pip install -r requirements.txt`
4. Start Command: `uvicorn app:app --host 0.0.0.0 --port $PORT`
5. الخطة: Free

## هيكل المشروع
```
├── app.py            # الباك إند (FastAPI + SQLite)
├── requirements.txt
├── Procfile
├── runtime.txt
├── users.db          # قاعدة البيانات (تُنشأ تلقائياً)
├── uploads/          # ملفات المستخدمين u_<id>/ (تُنشأ تلقائياً)
└── static/
    └── index.html    # الواجهة العربية
```
