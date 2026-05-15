from pathlib import Path


ROOT = Path(__file__).resolve().parent
DICT_DIR = Path(r"D:\tmp\anjian\pj\st\tmp\passhack\output\state\dicts")
USER_FILE = DICT_DIR / "builtin_usernames.txt"
PASS_FILE = DICT_DIR / "builtin_passwords.txt"
OUTPUT_DIR = ROOT / "login_sequences"
COMBO_FILE = OUTPUT_DIR / "default_weak_credentials.csv"
README_FILE = OUTPUT_DIR / "README.md"


def read_words(path):
    words = []
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        value = line.strip()
        if value and not value.startswith("#"):
            words.append(value)
    return words


def main():
    usernames = read_words(USER_FILE)
    passwords = read_words(PASS_FILE)
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    with COMBO_FILE.open("w", encoding="utf-8", newline="") as file_obj:
        file_obj.write("username,password\n")
        for username in usernames:
            for password in passwords:
                file_obj.write(f"{username},{password}\n")

    README_FILE.write_text(
        "\n".join(
            [
                "# Acunetix Login Notes",
                "",
                "- `default_weak_credentials.csv` is generated from the local passhack dictionaries.",
                "- `.lsr` files cannot be generated from only username/password dictionaries; they record browser actions, session validation, and optional restricted links.",
                "- Use `python awvs.py ... --login-default-weak` for Acunetix automatic login with `admin / 123456`.",
                "- Use `python awvs.py ... --login-user admin --login-pass 123456` to customize credentials while letting each target URL become the login URL.",
                "- Use `python awvs.py ... --lsr path\\to\\file.lsr` to upload an existing Login Sequence Recorder file to each target before scanning.",
                "",
            ]
        ),
        encoding="utf-8",
    )
    print(f"wrote {COMBO_FILE}")
    print(f"wrote {README_FILE}")


if __name__ == "__main__":
    main()
