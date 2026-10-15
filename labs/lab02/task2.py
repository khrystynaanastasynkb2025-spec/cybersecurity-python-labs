import argparse
import csv
import json
import logging
import re
from collections import Counter
from datetime import datetime
from pathlib import Path

# налаштування структурованого логування
logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def parse_log_line(line: str) -> dict | None:
    pattern = r'^(\S+) \S+ \S+ \[([\w:/]+\s[+\-]\d{4})\] "([A-Z]+) ([^"]+) HTTP/[\d.]+" (\d{3}) (\S+)'
    match = re.match(pattern, line)  # перевіряє чи відповідає шаблону
    if not match:
        return None

    ip, dt_str, method, uri, status, size = match.groups()

    try:
        log_time = datetime.strptime(
            dt_str, "%d/%b/%Y:%H:%M:%S %z"
        )  # перетвроює текст на дату,час
    except ValueError:
        log_time = None

    return {
        "ip": ip,
        "datetime": log_time,
        "method": method,
        "uri": uri,
        "status": int(status),
        "size": size,
    }


def detect_attacks(uri: str) -> list[str]:
    attacks = []
    if re.search(r"(union\s+select|or\s+1=1|[';]--)", uri, re.IGNORECASE):
        attacks.append("SQLi")
    if re.search(r"(\.\./|\.\.\\|/etc/passwd)", uri):
        attacks.append("Directory Traversal")
    if re.search(r"(<script.*?>.*?</script>|alert\(.*?\))", uri, re.IGNORECASE):
        attacks.append("XSS")
    return attacks


def analyze_access_log(  # функція об'єднює всі попередні
    log_path: Path, output_path: Path, min_status: int, top_n: int, file_format: str
):
    if not log_path.exists():  # перевіряє існування файлу
        logger.error(f"Файл логу не знайдено за шляхом: {log_path}")
        return

    logger.info(f"Loading access log from {log_path}")

    entries = []  # список усіх успішно розібраних записів
    min_time = None
    max_time = None

    try:
        with open(log_path, "r", encoding="utf-8") as f:
            for line in f:
                parsed = parse_log_line(line.strip())
                if parsed:
                    entries.append(parsed)  # якщо розібрав то додаємо у список
                    if parsed["datetime"]:
                        if min_time is None or parsed["datetime"] < min_time:
                            min_time = parsed["datetime"]
                        if max_time is None or parsed["datetime"] > max_time:
                            max_time = parsed["datetime"]
    except UnicodeDecodeError as e:
        logger.error(
            f"Помилка кодування файлу ({log_path}): файл не в форматі utf-8. Деталі: {e}"
        )
        return
    except IOError as e:
        logger.error(f"Помилка введення-виведення при читанні файлу ({log_path}): {e}")
        return
    except Exception as e:
        logger.error(f"Непередбачена помилка під час читання файлу логу: {e}")
        return

    min_time_str = min_time.strftime("%Y-%m-%d %H:%M:%S") if min_time else "N/A"
    max_time_str = max_time.strftime("%Y-%m-%d %H:%M:%S") if max_time else "N/A"
    logger.info(
        f"Processed {len(entries)} log entries from {min_time_str} to {max_time_str}."
    )

    # аналіз помилок та підрахунок через counter
    error_ips = Counter()
    ip_status_details = {}  # IP - Counter(status_code)
    detected_attacks_list = []

    for entry in entries:
        status = entry["status"]
        ip = entry["ip"]
        uri = entry["uri"]

        if status >= min_status:  # перевірка статусу
            error_ips[ip] += 1
            if ip not in ip_status_details:
                ip_status_details[ip] = Counter()
            ip_status_details[ip][status] += 1

        # пошук атак
        attacks = detect_attacks(uri)
        for attack in attacks:
            detected_attacks_list.append({"ip": ip, "attack": attack, "uri": uri})

    top_error_ips = error_ips.most_common(top_n)

    print(f"\n=== Top-{top_n} IP Addresses with Error Statuses (4xx/5xx) ===")
    for ip, count in top_error_ips:
        statuses_str = ", ".join(
            [f"{code}: {cnt}" for code, cnt in ip_status_details[ip].items()]
        )
        print(f"{ip}")
        print(f"{count} errors ({statuses_str})")

    print("\n=== Detected Attack Signatures ===")
    for item in detected_attacks_list:
        print(
            f'[ALERT] Potential {item["attack"]} attack from {item["ip"]}: "GET {item["uri"]}"'
        )

    # збереження звіту
    report_data = {
        "total_entries": len(entries),
        "top_error_ips": [
            {"ip": ip, "errors": count, "details": dict(ip_status_details[ip])}
            for ip, count in top_error_ips
        ],
        "attacks": detected_attacks_list,
    }
    try:
        output_path.parent.mkdir(parents=True, exist_ok=True)

        if file_format == "json":
            with open(output_path, "w", encoding="utf-8") as out_f:
                json.dump(report_data, out_f, indent=4, ensure_ascii=False)
        elif file_format == "csv":
            with open(output_path, "w", newline="", encoding="utf-8") as out_f:
                writer = csv.writer(out_f)
                writer.writerow(["IP", "Error Count", "Status Breakdown"])
                for ip, count in top_error_ips:
                    breakdown = str(dict(ip_status_details[ip]))
                    writer.writerow([ip, count, breakdown])

        logger.info(f"Analysis report saved to {output_path}")

    except IOError as e:
        logger.error(
            f"Помилка введення-виведення при збереженні файлу ({output_path}): {e}"
        )
    except Exception as e:
        logger.error(f"Сталася непередбачена помилка під час збереження звіту: {e}")

def main():
    parser = argparse.ArgumentParser(  # створює об'єкт який дозволяє передавати програмі параметри через командний рядок
        description="Аналізатор журналів веб-сервера (Nginx/Apache)"
    )
    parser.add_argument(
        "--log-file", type=str, required=True, help="Шлях до файлу access.log"
    )
    parser.add_argument(
        "--output",
        type=str,
        default="labs/lab02/data/web_analysis_report.json",
        help="Шлях до файлу звіту",
    )
    parser.add_argument(
        "--min-status", type=int, default=400, help="Мінімальний статус-код помилки"
    )
    parser.add_argument("--top", type=int, default=5, help="Кількість топ-IP")
    parser.add_argument(
        "--format",
        type=str,
        choices=["json", "csv"],
        default="json",
        help="Формат звіту",
    )

    args = parser.parse_args()

    analyze_access_log(
        log_path=Path(args.log_file),
        output_path=Path(args.output),
        min_status=args.min_status,
        top_n=args.top,
        file_format=args.format,
    )


if __name__ == "__main__":
    main()
