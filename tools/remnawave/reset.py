import subprocess

def main():
    query = (
        "SET lock_timeout='1500ms'; SET statement_timeout='16s'; "
        "SELECT pauk_remnawave_reset_due();"
    )
    command = [
        "/usr/bin/docker", "exec", "-i", "vpn-platform-postgres", "sh", "-ec",
        'exec psql -X -qAt -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB"',
    ]
    result = subprocess.run(command, input=query, text=True, capture_output=True, timeout=19)
    if result.returncode:
        raise SystemExit("PAUK traffic reset database request failed")
    count = int(result.stdout.strip())
    if count:
        print(f"Applied {count} traffic resets")
        subprocess.run(
            ["/usr/bin/systemctl", "--no-block", "start", "vpn-platform-access-reconciler.service"],
            check=True, timeout=3,
        )

if __name__ == "__main__":
    main()
