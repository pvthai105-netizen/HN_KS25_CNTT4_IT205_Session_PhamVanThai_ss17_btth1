raw_logs = [] 
processed_logs = []

def clean_and_parse_logs(raw_input_string):
    """
    Hàm nhận vào một chuỗi log thô, xóa ký tự đặc biệt sau đó tách thành danh
    sách các log riếng biệt
    """
    delete_table = str.maketrans("", "", "!@#$")
    cleaned_string = raw_input_string.translate(delete_table)
    log_list = [log.strip() for log in cleaned_string.split(';') if log.strip()]
    return log_list

def filter_logs(raw_Log_list):
    global processed_logs
    filter_log = [log for log in raw_Log_list if "ERROR" in log.upper() or "CRITICAL" in log.upper()]
    processed_logs = filter_log 
    return processed_logs

def mask_ip_address(process_list):
    global processed_logs
    masked_list = []
    for log in process_list:
        words  = log.split()
        new_word = []
        for word in words:
            if '.' in word:
                in_parts = word.split('.')
                if len(in_parts) == 4:
                    in_parts[2] = "*"
                    in_parts[3] = "*"
                    word = ".".join(in_parts)
            new_word.append(word)
        masked_log = ' '.join(new_word)
        masked_list.append(masked_log)
    processed_logs = masked_list
    return masked_list


def main():
    global raw_logs
    global processed_logs
    while True:
        choice = input("""============= SECURITY LOG ANALYZER =============
1. Nhập và làm sạch dữ liệu Log thô
2. Lọc các Log cảnh báo mức độ cao (ERROR/CRITICAL)
3. Mã hóa địa chỉ IP (Masking)
4. Đóng hệ thống
=================================================
Chọn chức năng (1-4):""")
        match choice:
            case "1":
                print("--- Nạp dữ liệu ---")
                raw_input = input("Nhập chuỗi log thô (cách nhau bởi dấu ;):")
                raw_logs = clean_and_parse_logs(raw_input)
                print(f"Tồng số log đã nạp thành công: {len(raw_logs)}")
                for i, log in enumerate(raw_logs,1):
                    print(f"Log {i}: {log}")

            case "2":
                print("--- Lọc Cảnh Báo ---")
                if not raw_logs:
                    print("Hệ thống chưa có dữ liệu")
                    continue
                filter_logs(raw_logs)
                print(f"Tìm thấy {len(processed_logs)} cảnh báo nguy hiểm")
                for log in processed_logs:
                    print(f"- {log}")
            case "3":
                print("--- Mã Hóa IP ---")
                if not processed_logs:
                    print("Thông báo: Chưa có log cảnh báo nào được lọc. Vui lòng chạy Chức năng 2 trước!")
                    continue  
                mask_data = mask_ip_address(processed_logs)              
                print("Báo cáo log an toàn:")
                for i, log in enumerate(mask_data, 1):
                    print(f"{i}. {log}")

            case "4":
                print("Đã đóng hệ thống")
                break
            case _:
                print("Không có lựa chọn này")

main()