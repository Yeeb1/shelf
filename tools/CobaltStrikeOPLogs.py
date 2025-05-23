import argparse
import csv
import os
from datetime import datetime, timedelta

def extract_raw_log_entries(base_path, shift_hours=0):
    entries = []

    for root, _, files in os.walk(base_path):
        for file in files:
            if not file.startswith("beacon_") or not file.endswith(".log"):
                continue

            full_path = os.path.join(root, file)

            rel_path = os.path.relpath(full_path, base_path)
            path_parts = rel_path.split(os.sep)
            if len(path_parts) < 3:
                continue

            date_folder = path_parts[0]
            ip_address = path_parts[1]
            beacon_id = file[len("beacon_"):-len(".log")]

            metadata = {
                "user": "unknown",
                "computer": "unknown",
                "process": "unknown",
                "pid": "unknown",
                "os": "unknown",
                "version": "unknown",
                "build": "unknown",
                "beacon_arch": "unknown"
            }

            checkin_timestamp = None
            checkin_line_number = None

            try:
                with open(full_path, "r", encoding="utf-8", errors='ignore') as f:
                    lines = f.readlines()

                for i, meta_line in enumerate(lines, start=1):
                    if "[metadata]" in meta_line:
                        try:
                            date_str = meta_line[:5]
                            time_str = meta_line[6:14]
                            checkin_dt = datetime.strptime(f"{date_str} {time_str}", "%m/%d %H:%M:%S")
                            checkin_dt += timedelta(hours=shift_hours)
                            checkin_timestamp = checkin_dt.strftime("%m/%d %H:%M:%S")
                            checkin_line_number = i

                            parts = meta_line.split(";")
                            for part in parts:
                                part = part.strip()
                                if ":" not in part:
                                    continue
                                key, value = part.split(":", 1)
                                key = key.strip().lower().replace(" ", "_")
                                value = value.strip()
                                if key in metadata:
                                    metadata[key] = value
                        except Exception as e:
                            print(f"Error parsing metadata in {full_path}:{i}: {e}")
                        break  # only first metadata

                if checkin_timestamp:
                    checkin_entry = {
                        "raw_timestamp": checkin_timestamp,
                        "operator": "CHECKIN",
                        "command": "initial check-in",
                        "beacon_id": beacon_id,
                        "ip_address": ip_address,
                        "date_folder": date_folder,
                        "line": f"{full_path}:{checkin_line_number or 1}",
                        **metadata
                    }
                    entries.append(checkin_entry)

                for i, line in enumerate(lines, start=1):
                    if "[input]" not in line:
                        continue

                    line = line.strip()
                    if len(line) < 20:
                        continue

                    try:
                        date_str = line[:5]
                        time_str = line[6:14]
                        dt = datetime.strptime(f"{date_str} {time_str}", "%m/%d %H:%M:%S")
                        dt += timedelta(hours=shift_hours)
                        raw_ts = dt.strftime("%m/%d %H:%M:%S")

                        start_op = line.find("<") + 1
                        end_op = line.find(">", start_op)
                        operator = line[start_op:end_op] if start_op > 0 and end_op > start_op else "unknown"

                        command_part = line.split(">", 1)
                        command = command_part[1].strip() if len(command_part) > 1 else ""

                        entry = {
                            "raw_timestamp": raw_ts,
                            "operator": operator,
                            "command": command,
                            "beacon_id": beacon_id,
                            "ip_address": ip_address,
                            "date_folder": date_folder,
                            "line": f"{full_path}:{i}",
                            **metadata
                        }

                        entries.append(entry)

                    except Exception as e:
                        print(f"Skipping {full_path}:{i}: {e}")
                        continue

            except Exception as e:
                print(f"ERROR READING {full_path}: {e}")

    return entries

def save_to_csv(entries, output_file):
    with open(output_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "raw_timestamp",
            "operator",
            "command",
            "beacon_id",
            "ip_address",
            "date_folder",
            "user",
            "computer",
            "process",
            "pid",
            "os",
            "version",
            "build",
            "beacon_arch",
            "line"
        ])
        writer.writeheader()
        for entry in entries:
            writer.writerow(entry)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("log_dir", help="Path to logs directory")
    parser.add_argument("-o", "--output", default="operator_log.csv", help="Output CSV file name")
    parser.add_argument("--shift-time", type=int, default=0, help="Shift timestamps by N hours (+/-)")
    args = parser.parse_args()

    entries = extract_raw_log_entries(args.log_dir, shift_hours=args.shift_time)
    print(f"Total raw lines written: {len(entries)}")
    save_to_csv(entries, args.output)
    print(f"Saved to {args.output}")

if __name__ == "__main__":
    main()
