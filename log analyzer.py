import re
import csv

# configuration

log_file = "security.log"
report_file = "report.txt"
csv_file = "analysis.csv"
brute_force_threshold = 5

# read the log file

def read_logs(file_name):
    with open(file_name,"r") as file:
        logs = file.readlines()
    return logs

# analyze the log

def analyze_log(logs):
    total_entries = 0
    successful_logins = 0
    failed_logins = 0
    failed_ip_count = {}
    user_activity = {}

    for line in logs:
        total_entries +=1

        #extract name

        user_match = re.search(r"user=(\w+)",line)
        if user_match:
            username = user_match.group(1)
        else:
            username = "Unknown"
        
        #extract ip 

        ip_match = re.search(r"ip=([\d\.]+)", line)
        if ip_match:
            ip_address = ip_match.group(1)
        else:
            ip_address = "Unknown"
        
        if username not in user_activity:
            user_activity[username] = 1
        else:
            user_activity[username] += 1

        #count login status 
        if "login_success" in line.lower():
            successful_logins += 1
        elif "login_failed" in line.lower():
            failed_logins += 1

            if ip_address not in failed_ip_count:
                failed_ip_count[ip_address] = 1
            else:
                failed_ip_count[ip_address] += 1
        
    return total_entries, successful_logins, failed_logins, failed_ip_count, user_activity

# detect attacks

def detect_attacks(failed_ip_counts):
    suspicious_ips=[]
    for ip, count in failed_ip_counts.items():
        if count >= brute_force_threshold:
            suspicious_ips.append((ip,count))
    return suspicious_ips

#export CSV

def export_csv(failed_ip_count):
    with open(csv_file, "w", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(["IP Address", "Failed Attempts"])
        for ip, count in failed_ip_count.items():
            writer.writerow([ip, count])

# save report

def save_report(total_entries, successful_logins, failed_logins, most_active_user, failed_ip_count, suspicious_ips):
    with open(report_file,"w") as report:
        report.write("===== LOG ANALYSIS REPORT =====\n\n")
        report.write(f"Total Entries : {total_entries}\n")
        report.write(f"Successful Logins : {successful_logins}\n")
        report.write(f"Failed Logins : {failed_logins}\n\n")
        report.write(f"Most Active User : {most_active_user}\n\n")
        report.write("Failed Login IPs\n")

        for ip, count in failed_ip_count.items():
            report.write(f"{ip} -> {count}\n")
        report.write("\nThreat Detection\n")

        if len(suspicious_ips) > 0:
            for ip, count in suspicious_ips:
                report.write(f"ALERT: {ip} - {count} failed attempts\n")
        else:
            report.write("No threats detected\n")

# main program

logs = read_logs(log_file)
total_entries, successful_logins, failed_logins, failed_ip_count, user_activity = analyze_log(logs)
suspicious_ips = detect_attacks(failed_ip_count)
if len(user_activity) > 0:
    most_active_user = max(user_activity, key=user_activity.get)
else:
    most_active_user = "None"

# display result

print("\n===== LOG ANALYSIS REPORT =====")
print("Total Entries      :", total_entries)
print("Successful Logins  :", successful_logins)
print("Failed Logins      :", failed_logins)
print("\nMost Active User   :", most_active_user)
print("\nFailed Login IPs")

for ip, count in failed_ip_count.items():
    print(ip, "->", count)
print("\nThreat Detection")

if len(suspicious_ips) > 0:
    for ip, count in suspicious_ips:
        print("ALERT:", ip, "-", count, "failed attempts")
else:
    print("No threats detected")

#save files

save_report(total_entries, successful_logins, failed_logins, most_active_user, failed_ip_count, suspicious_ips)
export_csv(failed_ip_count)

print("\nReport saved to", report_file)
print("CSV exported to", csv_file)