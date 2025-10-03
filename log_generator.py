import json
import random
import time
import requests
from datetime import datetime
from faker import Faker
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed

# Конфигурация
from config import WEBHOOK_URL, TOKENS, BATCH_SIZE

fake = Faker()

class LogGenerator:
    def __init__(self, bearer_token):
        self.session = requests.Session()
        self.session.headers.update({
            'Authorization': f'Bearer {bearer_token}',
            'Content-Type': 'application/json'
        })
        
        self.severities = ['info', 'warn', 'error', 'critical']
        self.statuses = ['clear', 'active', 'acknowledged', 'suppressed']
        self.environments = ['dev', 'staging', 'prod']
        self.sites = ['USOAK', 'USDFW', 'USNYC', 'USSEA', 'CATOR']
        self.device_types = ['Switch', 'Router', 'Server', 'Firewall', 'Load Balancer']
        self.manufacturers = ['Cisco', 'Meraki', 'Juniper', 'Dell', 'HPE']
        self.network_types = ['Corporate', 'DMZ', 'Guest', 'Management']
        
    def generate_host_name(self):
        site = random.choice(self.sites)
        location = f"{random.randint(1,999):03d}"
        device_type = random.choice(['ACDMSWE', 'RTRCOR', 'SRVAPP', 'FWDMZ'])
        number = f"{random.randint(1,999):03d}"
        return f"{site}{location}{device_type}{number}"
    
    def generate_ip_address(self):
        return f"{random.randint(10,252)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
    
    def generate_serial_number(self):
        chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        return f"{''.join(random.choices(chars, k=4))}-{''.join(random.choices(chars, k=4))}-{''.join(random.choices(chars, k=4))}"
    
    def generate_device_info(self):
        manufacturer = random.choice(self.manufacturers)
        device_type = random.choice(self.device_types)
        model = f"{manufacturer} {device_type} {random.choice(['24', '48'])}{'FP' if random.random() > 0.5 else ''}"
        return {
            'manufacturer': manufacturer,
            'model': model,
            'info': f"{model} Cloud Managed {'PoE ' if 'FP' in model else ''}{device_type}"
        }
    
    def generate_datasource_info(self):
        interfaces = [
            "Network Interfaces-Port",
            "CPU Utilization",
            "Memory Usage", 
            "Disk Space",
            "Temperature Sensors",
            "Power Supply Status"
        ]
        
        datapoints = {
            "Network Interfaces-Port": {
                "datapoint": "Status",
                "threshold": "> 1",
                "description": "If the interface is under administrative maintenance, we return a 0. Otherwise, we return the value of OperState. Status code summary below:\n\nStatus codes:\n-1=Alerting Disabled, as Interface doesn't match alert enabling properties,\n0=Administratively down,\n1=Up - Ready to pass packets,\n2=Down,\n3=Testing - in a test mode,\n4=Unknown - status cannot be determined,\n5=Dormant - interface is not actually in a condition to pass packets (i.e., it is not 'up') but is in a \"pending\" state, waiting for some external event.,\n6=Not Present - some component is missing,\n7=Lower Layer Down - down due to state of a lower-layer interface(s)."
            },
            "CPU Utilization": {
                "datapoint": "CPUBusyPercent",
                "threshold": "> 90",
                "description": "CPU utilization percentage across all cores"
            },
            "Memory Usage": {
                "datapoint": "MemoryUtilization",
                "threshold": "> 85",
                "description": "Memory usage percentage"
            }
        }
        
        interface = random.choice(interfaces)
        port_id = random.randint(1, 48) if "Port" in interface else random.randint(1, 10)
        datasource_name = f"{interface} {port_id} [ID:{port_id}]" if "Port" in interface else f"{interface} [ID:{port_id}]"
        
        datapoint_info = datapoints.get(interface.split('-')[0], {
            "datapoint": "Status",
            "threshold": "> 1",
            "description": "Generic monitoring datapoint"
        })
        
        return {
            'name': datasource_name,
            'datapoint': datapoint_info['datapoint'],
            'threshold': datapoint_info['threshold'],
            'description': datapoint_info['description'],
            'datasource_description': f"Collects {interface.lower()} performance and operational stats."
        }

    def generate_log_entry(self):
        host = self.generate_host_name()
        device = self.generate_device_info()
        datasource = self.generate_datasource_info()
        
        log_entry = {
            "severity": random.choice(self.severities),
            "host": host,
            "status": random.choice(self.statuses),
            "site_name": random.choice(["", "Main Office", "Branch Office", "Data Center"]),
            "env": random.choice(self.environments),
            "tags": {
                "device_url": f"https://acme.logicmonitor.com/santaba/uiv3/device/index.jsp#tree/-d-{random.randint(100,9999)}",
                "url": f"https://acme.logicmonitor.com/santaba/uiv4/alert#detail~id=LMD{random.randint(1000000,9999999)}&type=alert",
                "datapoint": datasource['datapoint'],
                "datapoint_description": datasource['description'],
                "datasource": datasource['name'],
                "datasource_description": datasource['datasource_description'],
                "alert_id": f"DS{random.randint(10000000,99999999)}",
                "threshold": datasource['threshold'],
                "host_info": device['info'],
                "host_ip": self.generate_ip_address(),
                "host_manufacturer": device['manufacturer'],
                "host_model": device['info'],
                "host_serial_number": self.generate_serial_number(),
                "network_type": random.choice(self.network_types)
            },
            "title": f"{host} has reported {datasource['name']} to be in alert due to {datasource['datapoint']} threshold being breached.",
            "manager": "Logicmonitor",
            "aiops_data": random.choice([True, False]),
            "cribl_pipe": [
                "logicmonitor",
                random.choice(["passthru", "enrichment", "filtering"])
            ]
        }
        
        return log_entry

    def send_single_log(self, log_entry, log_num):
        """Отправляет один лог как отдельный объект"""
        try:
            response = self.session.post(
                WEBHOOK_URL,
                json=log_entry,
                timeout=30
            )
            
            if response.status_code in [200, 201, 202]:
                print(f"✅ Лог {log_num}: отправлен успешно")
                return True
            else:
                print(f"❌ Лог {log_num}: Ошибка {response.status_code} - {response.text}")
                return False
                
        except requests.exceptions.RequestException as e:
            print(f"❌ Лог {log_num}: Ошибка сети - {str(e)}")
            return False
        except Exception as e:
            print(f"❌ Лог {log_num}: Неожиданная ошибка - {str(e)}")
            return False

    def send_logs_batch(self, logs_batch, batch_num):
        """Отправляет батч логов в формате events"""
        try:
            payload = {"events": logs_batch}
            
            response = self.session.post(
                WEBHOOK_URL,
                json=payload,
                timeout=30
            )
            
            if response.status_code in [200, 201, 202]:
                print(f"✅ Батч {batch_num}: {len(logs_batch)} логов отправлено успешно")
                return True
            else:
                print(f"❌ Батч {batch_num}: Ошибка {response.status_code} - {response.text}")
                return False
                
        except requests.exceptions.RequestException as e:
            print(f"❌ Батч {batch_num}: Ошибка сети - {str(e)}")
            return False
        except Exception as e:
            print(f"❌ Батч {batch_num}: Неожиданная ошибка - {str(e)}")
            return False

    def generate_and_send_logs(self, integration_index):
        """Генерирует и отправляет логи для одной интеграции"""
        total_sent = 0
        success_count = 0
        
        for i in range(BATCH_SIZE):
            log_entry = self.generate_log_entry()
            
            max_retries = 3
            for attempt in range(max_retries):
                if self.send_single_log(log_entry, f"int#{integration_index}-{i+1}"):
                    total_sent += 1
                    success_count += 1
                    break
                if attempt < max_retries - 1:
                    time.sleep(2 ** attempt)
        
        return success_count == BATCH_SIZE, total_sent

def main():
    print("🔧 LogicMonitor Log Generator (Отправка по одному логу)")
    print("=" * 60)
    print(f"🎯 Endpoint: {WEBHOOK_URL}")
    print(f"📦 Логов на интеграцию: {BATCH_SIZE}")
    print(f"🔗 Интеграций (токенов): {len(TOKENS)}")

    start_time = time.time()

    results = []
    with ThreadPoolExecutor(max_workers=len(TOKENS)) as executor:
        future_to_idx = {}
        for idx, token in enumerate(TOKENS, start=1):
            gen = LogGenerator(bearer_token=token)
            future = executor.submit(gen.generate_and_send_logs, idx)
            future_to_idx[future] = idx
        
        for future in as_completed(future_to_idx):
            ok, sent = future.result()
            results.append((ok, sent))

    duration = time.time() - start_time
    total_sent = sum(sent for ok, sent in results)
    ok_cnt = sum(1 for ok, _ in results if ok)
    fail_cnt = len(results) - ok_cnt

    print("\n" + "=" * 60)
    print("📊 ИТОГОВАЯ СТАТИСТИКА")
    print("=" * 60)
    print(f"⏱️  Время выполнения: {duration:.2f} секунд")
    print(f"📤 Всего логов отправлено: {total_sent}")
    print(f"✅ Успешных интеграций: {ok_cnt}")
    print(f"❌ Неудачных интеграций: {fail_cnt}")
    if duration > 0:
        print(f"📈 Скорость: {total_sent/duration:.2f} логов/сек")
    if fail_cnt == 0:
        print("🎉 Все интеграции отправили логи успешно!")
    else:
        print("⚠️ Некоторые интеграции завершились с ошибками")

if __name__ == "__main__":
    main()