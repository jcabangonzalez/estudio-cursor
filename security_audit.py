import time

def manage_sensitive_file():
    file = None
    try:
        # 1. Cambiamos el nombre del archivo de entrada
        print("🔒 Attempting to open 'secure_config.txt'...")
        file = open("secure_config.txt", "r")
        content = file.read()
        
    except FileNotFoundError:
        print("❌ ERROR: File not found. Please ensure 'secure_config.txt' exists.")
        
    else:
        print("✅ File read successful.")
        
        has_number = False
        for char in content:
            if char.isdigit():
                has_number = True

        if has_number:
            print("🛡️ Security: The key includes numbers.")
            log_status = "SECURE: Numbers detected"
        else:
            print("⚠️ ALERT: The key DOES NOT have numbers.")
            log_status = "WARNING: No numbers detected"

        # 2. Cambiamos el nombre del archivo de salida (Log)
        log_file = open("security_log.txt", "a")
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
        log_file.write(f"[{timestamp}] Access OK - {log_status}\n")
        log_file.close()

    finally:
        if file:
            file.close()
            print("🔒 System: Connection closed safely.")

manage_sensitive_file()