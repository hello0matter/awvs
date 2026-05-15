# Acunetix Login Notes

- `default_weak_credentials.csv` is generated from the local passhack dictionaries.
- `.lsr` files cannot be generated from only username/password dictionaries; they record browser actions, session validation, and optional restricted links.
- Use `python awvs.py ... --login-default-weak` for Acunetix automatic login with `admin / 123456`.
- Use `python awvs.py ... --login-user admin --login-pass 123456` to customize credentials while letting each target URL become the login URL.
- Use `python awvs.py ... --lsr path\to\file.lsr` to upload an existing Login Sequence Recorder file to each target before scanning.
