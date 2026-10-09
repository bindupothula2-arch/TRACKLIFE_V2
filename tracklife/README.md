# TrackLife 💚
Symptom tracker, medical history and medicine reminders for patients and doctors. English + Telugu (తెలుగు).

## What's inside
- **Database**: PostgreSQL when `DATABASE_URL` is set (free on Neon or Supabase, data survives redeploys). With no `DATABASE_URL` it uses a local SQLite file for easy testing.
- **Dashboard**: patient (symptoms, history, medicines, reminders, assistant, share with doctor) and doctor (shared patients' timeline + medicines).
- **Chatbot**: uses Claude if `ANTHROPIC_API_KEY` is set, otherwise a safe built-in fallback. Always ends with a suggested doctor type.
  In-depth drug/dose/interaction questions are blocked with an error message plus a doctor referral.
- **Voice assistant** (for people who can't read well): a big microphone button (also floating on every page) listens in Telugu or English and answers aloud in very simple words. Tap-a-picture buttons (fever, headache, cough...) work without typing. Say "my medicines" to hear today's medicine times; reminders are spoken aloud too. Uses the browser's built-in speech, so no extra cost. Works best in Chrome/Edge (Android, desktop). Telugu speech needs a Telugu voice on the device (Android: Settings > Text-to-speech).
- **Reports**: patients upload PDF, PNG, JPG or TXT files (max 5 MB). They are sorted into Lab results, Scans, Prescriptions, Discharge summaries and Other (auto-detected or chosen), with date, notes, download and delete. Doctors see the reports of patients who shared access.
- **Report analysis**: text in PDF/TXT files is read, names/phones/emails are removed, then summarised (key findings and which doctor type to discuss with). It never gives diagnosis or drug advice. Without `ANTHROPIC_API_KEY` a simple rule-based version finds lab-style values. Scanned images are stored but not read.
- **Privacy**: all medical fields and profile are encrypted at rest (Fernet). The AI receives only an anonymous ID plus condition/symptom/medicine names; name, phone, email and age are never sent, and emails/phone numbers in typed text are scrubbed.

## Run locally
    pip install -r requirements.txt
    python app.py          # open http://localhost:5000
Optional: `export ANTHROPIC_API_KEY=...` and choose any model with `export AI_MODEL=claude-opus-5-5` (default `claude-sonnet-5-5`).

## Put it on GitHub and get a live link
1. Create a new GitHub repo, then:
       git init && git add . && git commit -m "TrackLife"
       git branch -M main
       git remote add origin https://github.com/<you>/tracklife.git
       git push -u origin main
2. Go to render.com > New > Blueprint > pick the repo (uses `render.yaml`, free plan). You get a link like `https://tracklife.onrender.com`.
3. Create a free Postgres database at neon.tech (or supabase.com) and copy its connection string.
4. In Render > Environment, add:
   - `DATABASE_URL` = the connection string
   - `FERNET_KEY` = output of `python -c "from cryptography.fernet import Fernet;print(Fernet.generate_key().decode())"`
   - `ANTHROPIC_API_KEY` (optional, for the AI chatbot)
   Keep `FERNET_KEY` safe and unchanged. Losing it means stored data cannot be decrypted. The app refuses to start with Postgres if the keys are missing, so data is never locked by accident.
5. Tables are created automatically on first start.

## Important notes
- Passwords are stored only as hashes and cannot be displayed. The dashboard shows the password you typed at login, for this session only.
- Files are stored encrypted inside the database. Neon's free plan has about 0.5 GB, so storage fills up after roughly 100 reports of 5 MB. For heavy use, move files to object storage.
- This is a learning/demo build. Real HIPAA compliance needs a signed BAA with your host and AI provider, audit logs, and a security review. The assistant gives general guidance, not diagnosis.
