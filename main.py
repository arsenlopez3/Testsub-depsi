import base64
import json
import os
import re
import socket
import subprocess
import time
import shutil
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import quote, urlparse, parse_qs
import requests

CONFIG_PATH = "public/config.json"
TEST_URL = "https://www.gstatic.com/generate_204"
GEO_CACHE = {}

def load_config():
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
                if "profiles" in data:
                    return data
        except Exception:
            pass
    return {"profiles": {"default": {"brand_name": "ArsenVPN", "total_gb": 50, "expire_days": 30, "personal": [], "subs": [], "top_count": 20}}}

def get_flag_emoji(country_code):
    if not country_code or len(country_code) != 2:
        return "🌐"
    country_code = country_code.upper()
    return chr(127397 + ord(country_code[0])) + chr(127397 + ord(country_code[1]))

def extract_host_port(node_link):
    try:
        if node_link.startswith("vmess://"):
            b64_data = node_link.replace("vmess://", "")
            b64_data += "=" * (-len(b64_data) % 4)
            decoded = base64.b64decode(b64_data).decode("utf-8", errors="ignore")
            vmess_json = json.loads(decoded)
            return vmess_json.get("add", ""), int(vmess_json.get("port", 443))
        else:
            parsed = urlparse(node_link.split("#")[0])
            host = parsed.hostname
            port = parsed.port or 443
            return host, port
    except Exception:
        return None, None

def tcp_ping(host, port, timeout=2.0):
    if not host or not port:
        return False
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False

def rename_node(node_link, new_name):
    try:
        if node_link.startswith("vmess://"):
            b64_data = node_link.replace("vmess://", "")
            b64_data += "=" * (-len(b64_data) % 4)
            decoded = base64.b64decode(b64_data).decode("utf-8", errors="ignore")
            vmess_json = json.loads(decoded)
            vmess_json["ps"] = new_name
            new_b64 = base64.b64encode(json.dumps(vmess_json, ensure_ascii=False).encode("utf-8")).decode("utf-8")
            return "vmess://" + new_b64
        elif "#" in node_link:
            base_part = node_link.split("#")[0]
            return f"{base_part}#{quote(new_name)}"
        else:
            return f"{node_link}#{quote(new_name)}"
    except Exception:
        return node_link

def fetch_and_decode_subs(sub_urls):
    raw_nodes = []
    pattern = re.compile(r"^(vless|vmess|trojan|ss|ssr|tuic|hysteria2)://", re.IGNORECASE)
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"}
    for url in sub_urls:
        url = url.strip()
        if not url: continue
        try:
            r = requests.get(url, headers=headers, timeout=15)
            content = r.text.strip()
            try:
                decoded = base64.b64decode(content).decode("utf-8", errors="ignore")
                if any(p in decoded for p in ["vless://", "vmess://", "trojan://", "ss://"]):
                    content = decoded
            except Exception:
                pass
            for line in content.splitlines():
                line = line.strip()
                if pattern.match(line):
                    raw_nodes.append(line)
        except Exception as e:
            print(f"[ERROR] Fetching sub {url} failed: {e}")
    return list(set(raw_nodes))

def parse_vless_to_xray(node_link):
    """پارسر اصلاح‌شده و مقاوم VLESS"""
    try:
        link = node_link.split("#")[0] if "#" in node_link else node_link
        parsed = urlparse(link)
        uuid = parsed.username
        host = parsed.hostname
        port = parsed.port or 443
        params = parse_qs(parsed.query)
        
        network = params.get("type", ["tcp"])[0]
        security = params.get("security", ["none"])[0]
        
        outbound = {
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": host,
                    "port": port,
                    "users": [{"id": uuid, "encryption": "none"}]
                }]
            },
            "streamSettings": {
                "network": network,
                "security": security
            }
        }
        
        flow = params.get("flow", [""])[0]
        if flow:
            outbound["settings"]["vnext"][0]["users"][0]["flow"] = flow
            
        if network == "ws":
            path = params.get("path", ["/"])[0]
            host_header = params.get("host", [host])[0]
            outbound["streamSettings"]["wsSettings"] = {
                "path": path,
                "headers": {"Host": host_header}
            }
        elif network == "tcp":
            header_type = params.get("headerType", ["none"])[0]
            outbound["streamSettings"]["tcpSettings"] = {"header": {"type": header_type}}
        elif network == "grpc":
            service_name = params.get("serviceName", [""])[0]
            outbound["streamSettings"]["grpcSettings"] = {"serviceName": service_name}
        
        if security == "tls":
            sni = params.get("sni", [""])[0] or params.get("host", [""])[0] or host
            fp = params.get("fp", ["chrome"])[0]
            outbound["streamSettings"]["tlsSettings"] = {
                "serverName": sni,
                "allowInsecure": True,
                "fingerprint": fp
            }
        elif security == "reality":
            sni = params.get("sni", [""])[0]
            fp = params.get("fp", ["chrome"])[0]
            pbk = params.get("pbk", [""])[0]
            sid = params.get("sid", [""])[0]
            spx = params.get("spx", ["/"])[0]
            outbound["streamSettings"]["realitySettings"] = {
                "serverName": sni,
                "fingerprint": fp,
                "publicKey": pbk,
                "shortId": sid,
                "spiderX": spx,
                "allowInsecure": True
            }
            
        return json.dumps(outbound)
    except Exception as e:
        return None

def convert_node(node_link, target_format):
    try:
        cmd = ["./subconverter/subconverter", "-g", "--generate-mode", "single", "--url", node_link, "--target", target_format, "-f"]
        res = subprocess.check_output(cmd, stderr=subprocess.PIPE, timeout=15)
        return res.decode("utf-8")
    except Exception:
        return None

def test_single_node(node_info):
    index, node_link = node_info
    host, port = extract_host_port(node_link)
    
    if not tcp_ping(host, port):
        return node_link, 0.0

    port_proxy = 10800 + (index % 1000)
    
    if node_link.startswith("vless://"):
        json_str = parse_vless_to_xray(node_link)
    else:
        json_str = convert_node(node_link, "xray")
    
    if not json_str:
        print(f"[TEST] Node {index} failed: Could not generate Xray config.")
        return node_link, 0.0
        
    try:
        outbound_config = json.loads(json_str)
    except Exception:
        return node_link, 0.0

    config_filename = f"temp_xray_{port_proxy}.json"
    full_config = {
        "log": {"loglevel": "warning"}, # تغییر به warning برای دیدن خطاها
        "inbounds": [{"port": port_proxy, "listen": "127.0.0.1", "protocol": "socks", "settings": {"udp": True}}],
        "outbounds": [outbound_config],
    }
    with open(config_filename, "w", encoding="utf-8") as f:
        json.dump(full_config, f)

    # اجرای Xray و ذخیره خطاها
    proc = subprocess.Popen(["./xray", "run", "-c", config_filename], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    time.sleep(2.0) # افزایش زمان انتظار به 2 ثانیه
    
    proxies = {"http": f"socks5h://127.0.0.1:{port_proxy}", "https": f"socks5h://127.0.0.1:{port_proxy}"}
    score = 0.0
    try:
        t0 = time.time()
        res = requests.get(TEST_URL, proxies=proxies, timeout=6)
        if res.status_code in [200, 204]:
            latency = time.time() - t0
            score = max(1.0, 10.0 - latency)
            print(f"[TEST] Node {index} SUCCESS! Latency: {latency:.2f}s | Score: {score:.2f}")
        else:
            print(f"[TEST] Node {index} failed: HTTP {res.status_code}")
    except Exception as e:
        # چاپ خطای دقیق Xray
        proc.terminate()
        stdout, stderr = proc.communicate()
        xray_error = stderr.decode('utf-8', errors='ignore').strip()
        if xray_error:
            print(f"[XRAY ERROR] Node {index}: {xray_error[:200]}")
        else:
            print(f"[TEST] Node {index} failed: Connection timed out.")
    finally:
        proc.terminate()
        proc.wait()
        if os.path.exists(config_filename):
            os.remove(config_filename)
    return node_link, score

def get_exit_country(node_info):
    index, node_link = node_info
    port_proxy = 20000 + (index % 1000)
    
    if node_link.startswith("vless://"):
        json_str = parse_vless_to_xray(node_link)
    else:
        json_str = convert_node(node_link, "xray")
        
    if not json_str:
        return node_link, ""
    try:
        outbound_config = json.loads(json_str)
    except Exception:
        return node_link, ""

    config_filename = f"temp_xray_geo_{port_proxy}.json"
    full_config = {
        "log": {"loglevel": "none"},
        "inbounds": [{"port": port_proxy, "listen": "127.0.0.1", "protocol": "socks", "settings": {"udp": True}}],
        "outbounds": [outbound_config],
    }
    with open(config_filename, "w", encoding="utf-8") as f:
        json.dump(full_config, f)

    proc = subprocess.Popen(["./xray", "run", "-c", config_filename], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1.5)
    
    proxies = {"http": f"socks5h://127.0.0.1:{port_proxy}", "https": f"socks5h://127.0.0.1:{port_proxy}"}
    country_code = ""
    try:
        res = requests.get("http://ip-api.com/json/", proxies=proxies, timeout=5)
        if res.status_code == 200:
            data = res.json()
            country_code = data.get("countryCode", "")
    except Exception:
        pass
    finally:
        proc.terminate()
        proc.wait()
        if os.path.exists(config_filename):
            os.remove(config_filename)
            
    return node_link, country_code

def create_info_node(total_gb, expire_days):
    info_title = f"📊 Traffic: {total_gb} GB | ⏳ Remaining: {expire_days} Days"
    dummy_vless = f"vless://00000000-0000-0000-0000-000000000000@127.0.0.1:8080?type=tcp#{quote(info_title)}"
    return dummy_vless

def generate_outputs(profile_name, final_nodes, total_gb, expire_days):
    profile_dir = os.path.join("public", profile_name)
    os.makedirs(profile_dir, exist_ok=True)
    info_node = create_info_node(total_gb, expire_days)
    all_nodes_with_info = [info_node] + final_nodes
    b64_out = base64.b64encode("\n".join(all_nodes_with_info).encode("utf-8")).decode("utf-8")
    with open(os.path.join(profile_dir, "sub.txt"), "w", encoding="utf-8") as f:
        f.write(b64_out)
    
    joined_nodes = "|".join(final_nodes)
    clash_yaml = convert_node(joined_nodes, "clash")
    if clash_yaml:
        with open(os.path.join(profile_dir, "clash.yaml"), "w", encoding="utf-8") as f:
            f.write(clash_yaml)
    singbox_json = convert_node(joined_nodes, "singbox")
    if singbox_json:
        with open(os.path.join(profile_dir, "singbox.json"), "w", encoding="utf-8") as f:
            f.write(singbox_json)
    print(f"✅ فایل‌های پروفایل {profile_name} ذخیره شدند.")

def cleanup_removed_profiles(active_profiles):
    os.makedirs("public", exist_ok=True)
    for item in os.listdir("public"):
        item_path = os.path.join("public", item)
        if os.path.isdir(item_path):
            if item not in active_profiles:
                try:
                    shutil.rmtree(item_path)
                except Exception:
                    pass

def main():
    config = load_config()
    profiles = config.get("profiles", {})
    cleanup_removed_profiles(profiles.keys())
    
    for prof_name, prof_data in profiles.items():
        print(f"\n--- پردازش پروفایل: {prof_name} ---")
        personal_nodes = prof_data.get("personal", [])
        sub_urls = prof_data.get("subs", [])
        top_count = prof_data.get("top_count", 20)
        brand_name = prof_data.get("brand_name", "ArsenVPN")
        total_gb = prof_data.get("total_gb", 50)
        expire_days = prof_data.get("expire_days", 30)

        dynamic_nodes = fetch_and_decode_subs(sub_urls)
        print(f"[INFO] Total nodes fetched: {len(dynamic_nodes)}")
        
        if not dynamic_nodes:
            final_nodes = personal_nodes
        else:
            indexed_nodes = list(enumerate(dynamic_nodes))
            tested_results = []
            
            print("[INFO] Testing speed of all nodes...")
            with ThreadPoolExecutor(max_workers=3) as executor: # کاهش تردها برای جلوگیری از ریسورس
                futures = [executor.submit(test_single_node, item) for item in indexed_nodes]
                for future in as_completed(futures):
                    link, score = future.result()
                    if link and score > 1.0: 
                        tested_results.append((link, score))

            print(f"[INFO] {len(tested_results)} nodes passed the speed test.")
            
            if tested_results:
                tested_results.sort(key=lambda x: x[1], reverse=True)
                top_candidates = tested_results[:int(top_count * 1.5)]
                
                print(f"[INFO] Detecting country for {len(top_candidates)} best nodes...")
                geo_results = []
                with ThreadPoolExecutor(max_workers=2) as executor:
                    futures = [executor.submit(get_exit_country, (i, item[0])) for i, item in enumerate(top_candidates)]
                    for future in as_completed(futures):
                        link, country_code = future.result()
                        geo_results.append((link, country_code))
                
                final_dynamic = []
                for link, score in tested_results:
                    for geo_link, country_code in geo_results:
                        if link == geo_link:
                            flag = get_flag_emoji(country_code) if country_code else "🌐"
                            final_dynamic.append((link, flag))
                            break
                    if len(final_dynamic) >= top_count:
                        break

                renamed_dynamic = []
                for idx, (node, flag) in enumerate(final_dynamic, start=1):
                    custom_title = f"{flag} {brand_name} - {idx:02d}"
                    renamed_dynamic.append(rename_node(node, custom_title))
            else:
                renamed_dynamic = []

            final_nodes = personal_nodes + renamed_dynamic

        generate_outputs(prof_name, final_nodes, total_gb, expire_days)

    print("\n🎉 عملیات با موفقیت تمام شد.")

if __name__ == "__main__":
    main()
