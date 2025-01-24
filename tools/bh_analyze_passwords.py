#!/usr/bin/env python3
import argparse
import csv
import json
import os
import sys
from datetime import datetime, timezone


class Colors:
    RED = "\033[91m"
    YELLOW = "\033[93m"
    BOLD = "\033[1m"
    RESET = "\033[0m"

def colorize(text, color):
    return f"{color}{text}{Colors.RESET}"

def bold(text):
    return f"{Colors.BOLD}{text}{Colors.RESET}"


def load_json_file(json_path):
    """Load and return JSON data from a file, or exit with error if not found."""
    if not os.path.isfile(json_path):
        print(f"[ERROR] JSON file not found: {json_path}")
        sys.exit(1)
    with open(json_path, 'r', encoding='utf-8') as f:
        return json.load(f)

def parse_epoch_time(epoch):
    """Convert integer epoch seconds to a datetime object in UTC, or None if invalid."""
    if isinstance(epoch, int) and epoch > 0:
        return datetime.fromtimestamp(epoch, tz=timezone.utc)
    return None

def days_diff_from_now(dt):
    """Return the difference in days between dt and now (in UTC). If dt is None, return None."""
    if not dt:
        return None
    return (datetime.now(timezone.utc) - dt).days

def filter_out_disabled_accounts(accounts_data):
    """Return only enabled accounts (Properties.enabled==True)."""
    filtered = []
    for acc in accounts_data:
        enabled = acc.get("Properties", {}).get("enabled", True)
        if enabled:
            filtered.append(acc)
    return filtered

def analyze_accounts(accounts_data, old_threshold, very_old_threshold):
    """
    Analyze password age, creation time, last logon, etc.
    Returns a list of dicts with analysis results.
    """
    results = []
    for entry in accounts_data:
        props = entry.get("Properties", {})
        sam = props.get("samaccountname", "").upper()
        if not sam:
            continue

        name = props.get("name", "UNKNOWN")

        whencreated_dt = parse_epoch_time(props.get("whencreated"))
        pwdlastset_dt = parse_epoch_time(props.get("pwdlastset"))

        lastlogon_dt = parse_epoch_time(props.get("lastlogon"))
        if not lastlogon_dt:
            lastlogon_dt = parse_epoch_time(props.get("lastlogontimestamp"))

        days_since_creation = days_diff_from_now(whencreated_dt)
        days_since_pwdset = days_diff_from_now(pwdlastset_dt)
        days_since_lastlogon = days_diff_from_now(lastlogon_dt)

        never_changed = False
        if whencreated_dt and pwdlastset_dt:
            if whencreated_dt.date() == pwdlastset_dt.date():
                never_changed = True

        is_old = False
        is_very_old = False
        if days_since_pwdset is not None:
            if days_since_pwdset >= very_old_threshold:
                is_very_old = True
            elif days_since_pwdset >= old_threshold:
                is_old = True

        results.append({
            "samaccountname": sam,
            "name": name,
            "whencreated_dt": whencreated_dt,
            "pwdlastset_dt": pwdlastset_dt,
            "lastlogon_dt": lastlogon_dt,
            "days_since_creation": days_since_creation,
            "days_since_pwdset": days_since_pwdset,
            "days_since_lastlogon": days_since_lastlogon,
            "never_changed_password": never_changed,
            "is_old_password": is_old,
            "is_very_old_password": is_very_old
        })

    return results

def sort_results(results, sort_by, descending=False):
    """
    Sort the results list in-place based on the specified field:
      - sort_by == 'creation'  => sort by days_since_creation
      - sort_by == 'pwdage'    => sort by days_since_pwdset
      - sort_by == 'lastlogon' => sort by days_since_lastlogon
      - sort_by == 'none' or anything else => no sorting
    """
    valid_sorts = {
        "creation": "days_since_creation",
        "pwdage": "days_since_pwdset",
        "lastlogon": "days_since_lastlogon"
    }
    if sort_by.lower() in valid_sorts:
        field = valid_sorts[sort_by.lower()]
        results.sort(key=lambda x: (x[field] if x[field] is not None else -999999), reverse=descending)

# --------------------------------------------------------------------------------
# REPORTING
# --------------------------------------------------------------------------------
def print_analysis_report(results, old_threshold, very_old_threshold, hide_normal=False):
    """
    Print a detailed console report for each account, plus summary.
    If 'hide_normal' is True, skip printing accounts with "password age is within normal range."
    """
    print("\n" + "="*70)
    print(bold("BASIC ANALYSIS REPORT"))
    print("="*70 + "\n")

    for r in results:
        sam = r["samaccountname"]
        name = r["name"]
        ds_creation = r['days_since_creation']
        ds_pwdset = r['days_since_pwdset']
        ds_logon = r['days_since_lastlogon']

        never_changed = r["never_changed_password"]
        is_very_old = r["is_very_old_password"]
        is_old = r["is_old_password"]

        is_normal = not never_changed and not is_very_old and not is_old

        if hide_normal and is_normal:
            continue

        print("-"*70)
        print(f"{bold('Account:')} {sam} ({name})")
        print(f"  Days since creation:       {ds_creation}")
        print(f"  Days since pwd last set:   {ds_pwdset}")
        print(f"  Days since last logon:     {ds_logon}")

        if never_changed:
            print("  " + colorize("[HIGH RISK] Password never changed since creation!", Colors.RED))
        elif is_very_old:
            print("  " + colorize(f"[WARNING] Password is VERY OLD (>= {very_old_threshold} days)!", Colors.RED))
        elif is_old:
            print("  " + colorize(f"[NOTICE] Password is OLD (>= {old_threshold} days).", Colors.YELLOW))
        else:
            if not hide_normal:
                print("  Password age is within normal range.")

    print("\n" + "="*70)
    print(bold("SUMMARY: VERY OLD PASSWORDS"))
    print("="*70)
    very_old = [x for x in results if x["is_very_old_password"]]
    if very_old:
        for x in very_old:
            ds_pwdset = x["days_since_pwdset"]
            print(f" - {x['samaccountname']} ({x['name']}), PwdAge={ds_pwdset} days")
    else:
        print("  None")

    print("\n" + "="*70)
    print(bold("SUMMARY: PASSWORD NEVER CHANGED"))
    print("="*70)
    never_changed_list = [x for x in results if x["never_changed_password"]]
    if never_changed_list:
        for x in never_changed_list:
            ds_creation = x["days_since_creation"]
            print(f" - {x['samaccountname']} ({x['name']}), Created={ds_creation} days ago")
    else:
        print("  None")

    print("-"*70 + "\n")

def write_csv(results, csv_file_path):
    """
    Write the entire results set to a CSV file for easy searching/filtering.

    CSV columns:
      samaccountname, name,
      days_since_creation, days_since_pwdset, days_since_lastlogon,
      never_changed_password, is_old_password, is_very_old_password
    """
    fieldnames = [
        "samaccountname",
        "name",
        "days_since_creation",
        "days_since_pwdset",
        "days_since_lastlogon",
        "never_changed_password",
        "is_old_password",
        "is_very_old_password"
    ]

    try:
        with open(csv_file_path, mode="w", newline="", encoding="utf-8") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()

            for r in results:
                row = {
                    "samaccountname": r["samaccountname"],
                    "name": r["name"],
                    "days_since_creation": r["days_since_creation"] if r["days_since_creation"] is not None else "",
                    "days_since_pwdset": r["days_since_pwdset"] if r["days_since_pwdset"] is not None else "",
                    "days_since_lastlogon": r["days_since_lastlogon"] if r["days_since_lastlogon"] is not None else "",
                    "never_changed_password": r["never_changed_password"],
                    "is_old_password": r["is_old_password"],
                    "is_very_old_password": r["is_very_old_password"]
                }
                writer.writerow(row)
        print(f"[INFO] CSV output written to: {csv_file_path}")
    except Exception as e:
        print(f"[ERROR] Failed to write CSV: {e}")

# --------------------------------------------------------------------------------
# ADVANCED ANALYSIS + FINDSIMILAR
# --------------------------------------------------------------------------------
def advanced_analysis(results, accounts_list, similar_timeframe):
    """
    Return an analysis report of which accounts are created/pwdset in a similar timeframe.
    """
    account_dict = { r["samaccountname"] : r for r in results }

    analysis_report = {}
    for acct in accounts_list:
        acct_upper = acct.strip().upper()
        if not acct_upper:
            continue
        if acct_upper not in account_dict:
            analysis_report[acct] = {
                "found": False,
                "similar_timeframe_accounts": []
            }
            continue

        this_acct_data = account_dict[acct_upper]
        this_creation_age = this_acct_data["days_since_creation"]
        this_pwd_age = this_acct_data["days_since_pwdset"]

        st_accounts = []
        for other_acct, other_data in account_dict.items():
            if other_acct == acct_upper:
                continue

            other_creation_age = other_data["days_since_creation"]
            other_pwd_age = other_data["days_since_pwdset"]

            match_creation = False
            match_pwd = False

            if (this_creation_age is not None and other_creation_age is not None):
                if abs(this_creation_age - other_creation_age) <= similar_timeframe:
                    match_creation = True
            if (this_pwd_age is not None and other_pwd_age is not None):
                if abs(this_pwd_age - other_pwd_age) <= similar_timeframe:
                    match_pwd = True

            if match_creation or match_pwd:
                st_accounts.append(other_acct)

        analysis_report[acct] = {
            "found": True,
            "data": this_acct_data,
            "similar_timeframe_accounts": st_accounts
        }

    return analysis_report

def print_advanced_analysis_report(analysis_report, similar_timeframe):
    """
    Print the advanced analysis (findsimilar) results.
    """
    print("\n" + "="*70)
    print(bold(f"ADVANCED ANALYSIS (Similar Timeframe = ±{similar_timeframe} days)"))
    print("="*70 + "\n")

    for acct, info in analysis_report.items():
        if not info["found"]:
            print(f"[NOT FOUND] {acct}")
            continue

        data = info["data"]
        sam = data["samaccountname"]
        name = data["name"]
        print("-"*70)
        print(f"{bold('Account:')} {sam} ({name})")
        print(f"  Creation Age (days):  {data['days_since_creation']}")
        print(f"  Password Age (days):  {data['days_since_pwdset']}")
        print(f"  Last Logon (days):    {data['days_since_lastlogon']}")

        if info["similar_timeframe_accounts"]:
            print("  Similar timeframe accounts:")
            for sa in info["similar_timeframe_accounts"]:
                print(f"    - {sa}")
        else:
            print("  No accounts matched similar timeframe.")

    print("-"*70 + "\n")

# --------------------------------------------------------------------------------
# SUBCOMMAND HANDLERS (ANALYSE, FINDSIMILAR, DUMP)
# --------------------------------------------------------------------------------
def cmd_analyse(args):
    """
    Handles the 'analyse' subcommand.
    """
    data = load_json_file(args.json)
    accounts_data = data.get("data", [])

    if args.ignore_disabled:
        accounts_data = filter_out_disabled_accounts(accounts_data)

    results = analyze_accounts(accounts_data, args.old_threshold, args.very_old_threshold)
    sort_results(results, args.sort_by, args.descending)

    print_analysis_report(results, args.old_threshold, args.very_old_threshold,
                          hide_normal=args.hide_normal)

    if args.csv_output:
        write_csv(results, args.csv_output)

def cmd_findsimilar(args):
    """
    Handles the 'findsimilar' subcommand.
    """
    data = load_json_file(args.json)
    accounts_data = data.get("data", [])

    if args.ignore_disabled:
        accounts_data = filter_out_disabled_accounts(accounts_data)

    results = analyze_accounts(accounts_data, args.old_threshold, args.very_old_threshold)
    sort_results(results, args.sort_by, args.descending)

    if not os.path.isfile(args.accounts):
        print(f"[ERROR] Accounts file not found: {args.accounts}")
        sys.exit(1)

    with open(args.accounts, "r", encoding="utf-8") as f:
        acct_list = [line.strip() for line in f if line.strip()]

    analysis_report = advanced_analysis(results, acct_list, args.similar_timeframe)
    print_advanced_analysis_report(analysis_report, args.similar_timeframe)

    if args.csv_output:
        write_csv(results, args.csv_output)

def cmd_dump(args):
    """
    Handles the 'dump' subcommand.
    Creates a CSV of accounts that changed their password in a specific timeframe.
    (Either days since or date range.)
    """
    from datetime import datetime, timezone

    # Additional date parsing helpers
    def parse_date_ymd(date_str):
        try:
            dt = datetime.strptime(date_str, "%Y-%m-%d")
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            return None

    def password_changed_in_range(item, start_dt, end_dt):
        pwd_dt = item.get("pwdlastset_dt")
        if not pwd_dt:
            return False
        if start_dt and pwd_dt < start_dt:
            return False
        if end_dt and pwd_dt > end_dt:
            return False
        return True

    data = load_json_file(args.json)
    accounts_data = data.get("data", [])

    if args.ignore_disabled:
        accounts_data = filter_out_disabled_accounts(accounts_data)

    results = analyze_accounts(accounts_data, args.old_threshold, args.very_old_threshold)

    filtered_results = []

    start_dt = None
    end_dt = None
    if args.changed_start:
        start_dt = parse_date_ymd(args.changed_start)
        if not start_dt:
            print(f"[ERROR] Invalid --changed-start date: {args.changed_start}")
            sys.exit(1)
    if args.changed_end:
        end_dt = parse_date_ymd(args.changed_end)
        if not end_dt:
            print(f"[ERROR] Invalid --changed-end date: {args.changed_end}")
            sys.exit(1)

    if start_dt or end_dt:
        for r in results:
            if password_changed_in_range(r, start_dt, end_dt):
                filtered_results.append(r)
    elif args.changed_since_days is not None:
        for r in results:
            ds_pwd = r["days_since_pwdset"]
            if ds_pwd is not None and ds_pwd <= args.changed_since_days:
                filtered_results.append(r)
    else:
        print("[ERROR] The 'dump' subcommand requires either --changed-since-days OR --changed-start/--changed-end.")
        sys.exit(1)

    sort_results(filtered_results, args.sort_by, args.descending)

    if not args.csv_output:
        print("[ERROR] 'dump' requires --csv-output to specify output file.")
        sys.exit(1)

    write_csv(filtered_results, args.csv_output)

    if not args.quiet:
        print("\n" + "="*70)
        print(bold(f"DUMP COMPLETE: {len(filtered_results)} ACCOUNTS"))
        print("="*70 + "\n")
        for r in filtered_results[:10]:
            ds_pwd = r['days_since_pwdset']
            ds_pwd_str = str(ds_pwd) if ds_pwd is not None else "N/A"
            pwd_dt = r['pwdlastset_dt']
            pwd_dt_str = pwd_dt.isoformat() if pwd_dt else "N/A"
            print(f" - {r['samaccountname']} changed {ds_pwd_str} days ago (pwdlastset={pwd_dt_str})")

        if len(filtered_results) > 10:
            print(f"[... +{len(filtered_results) - 10} more ...]\n")

# --------------------------------------------------------------------------------
# MAIN + SUBCOMMANDS
# --------------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Analyze password ages & creation times from BloodHound-like JSON using subcommands."
    )
    subparsers = parser.add_subparsers(dest="subcommand", required=True,
                                       help="Subcommand to run (analyse, findsimilar, dump).")

    # ----------------------------
    # SUBCOMMAND: analyse
    # ----------------------------
    parser_analyse = subparsers.add_parser("analyse", help="Standard password analysis.")
    parser_analyse.add_argument("--json", required=True, help="Path to the JSON file to analyze.")
    parser_analyse.add_argument("--old-threshold", type=int, default=90, help="Days for 'old' password (default=90).")
    parser_analyse.add_argument("--very-old-threshold", type=int, default=365, help="Days for 'very old' password (default=365).")
    parser_analyse.add_argument("--ignore-disabled", action="store_true", help="Ignore disabled accounts.")
    parser_analyse.add_argument("--sort-by", choices=["creation", "pwdage", "lastlogon", "none"], default="none",
                                help="Sort field (creation, pwdage, lastlogon, none). Default=none.")
    parser_analyse.add_argument("--descending", action="store_true", help="Sort descending.")
    parser_analyse.add_argument("--csv-output", help="If provided, writes all analysis results to CSV.")
    parser_analyse.add_argument("--hide-normal", action="store_true",
                                help="Do not print per-account detail if the password age is within normal range.")

    parser_analyse.set_defaults(func=cmd_analyse)

    # ----------------------------
    # SUBCOMMAND: findsimilar
    # ----------------------------
    parser_find = subparsers.add_parser("findsimilar", help="Find accounts with similar creation/pwdset timeframe.")
    parser_find.add_argument("--json", required=True, help="Path to the JSON file to analyze.")
    parser_find.add_argument("--accounts", required=True, help="Path to text file with accounts to check (one per line).")
    parser_find.add_argument("--similar-timeframe", type=int, default=7, help="Days difference for 'similar timeframe'.")
    parser_find.add_argument("--old-threshold", type=int, default=90, help="Days for 'old' password (default=90).")
    parser_find.add_argument("--very-old-threshold", type=int, default=365, help="Days for 'very old' password (default=365).")
    parser_find.add_argument("--ignore-disabled", action="store_true", help="Ignore disabled accounts.")
    parser_find.add_argument("--sort-by", choices=["creation", "pwdage", "lastlogon", "none"], default="none",
                             help="Sort field (creation, pwdage, lastlogon, none). Default=none.")
    parser_find.add_argument("--descending", action="store_true", help="Sort descending.")
    parser_find.add_argument("--csv-output", help="If provided, writes all analysis results to CSV.")
    parser_find.set_defaults(func=cmd_findsimilar)

    # ----------------------------
    # SUBCOMMAND: dump
    # ----------------------------
    parser_dump = subparsers.add_parser("dump", help="Dump to CSV all accounts that changed password in a timeframe.")
    parser_dump.add_argument("--json", required=True, help="Path to the JSON file to analyze.")
    parser_dump.add_argument("--old-threshold", type=int, default=90, help="For internal analysis (default=90).")
    parser_dump.add_argument("--very-old-threshold", type=int, default=365, help="For internal analysis (default=365).")
    parser_dump.add_argument("--ignore-disabled", action="store_true", help="Ignore disabled accounts.")
    parser_dump.add_argument("--sort-by", choices=["creation", "pwdage", "lastlogon", "none"], default="none",
                             help="Sort field (creation, pwdage, lastlogon, none). Default=none.")
    parser_dump.add_argument("--descending", action="store_true", help="Sort descending.")

    # Two ways to define timeframe:
    parser_dump.add_argument("--changed-since-days", type=int,
                             help="Dump accounts whose pwd last set is within X days. e.g. 30 => last 30 days.")
    parser_dump.add_argument("--changed-start", type=str,
                             help="Dump accounts whose pwd last set >= this date (YYYY-MM-DD).")
    parser_dump.add_argument("--changed-end", type=str,
                             help="Dump accounts whose pwd last set <= this date (YYYY-MM-DD).")

    parser_dump.add_argument("--csv-output", help="Output CSV file (REQUIRED for 'dump').")
    parser_dump.add_argument("--quiet", action="store_true", help="Suppress summary output.")
    parser_dump.set_defaults(func=cmd_dump)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
