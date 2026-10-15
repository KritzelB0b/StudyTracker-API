StudyTracker 2.5

1. BACKUP: export existing JSON before any changes.
2. Deploy main.py to Railway API first. No user_data migration: new public_preferences table only.
3. Deploy index.html, editor.html, sw.js, icon.svg, manifest.webmanifest to GitHub Pages.
4. Login via Data & Settings, enable precisely selected public sections. Public is OFF by default.
5. Test incognito /public/view and /sync (latter must return 401).
6. Advanced editing uses retained private editor.html within shared shell until full UI migration.

No file uploads are made public. This release does not implement a new private storage service.
