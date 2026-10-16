import base64
import json
import os
import re
import socket
import subprocess
import time
import shutil
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import quote, urlparse
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
        print(f"\n[DEBUG] Fetching sub: {url}")
        try:
            r = requests.get(url, headers=headers, timeout=15)
            print(f"[DEBUG] Status Code: {r.status_code}")
            content = r.text.strip()
            
            # چاپ ۱۰۰ کاراکتر اول برای بررسی
            print(f"[DEBUG] First 100 chars: {content[:100]}")
            
            try:
                decoded = base64.b64decode(content).decode("utf-8", errors="ignore")
                if any(p in decoded for p in ["vless://", "vmess://", "trojan://", "ss://"]):
                    content = decoded
                    print("[DEBUG] Content Base64 decoded successfully.")
            except Exception as e:
                print(f"[DEBUG] Base64 decode failed (maybe it's plain text): {e}")

            lines = content.splitlines()
            print(f"[DEBUG] Total lines in sub: {len(lines)}")
            
            found_in_this_sub = 0
            for line in lines:
                line = line.strip()
                if pattern.match(line):
                    raw_nodes.append(line)
                    found_in_this_sub += 1
            print(f"[DEBUG] Found {found_in_this_sub} valid nodes in this sub.")
            
        except Exception as e:
            print(f"[ERROR] Fetching sub {url} failed: {e}")
            
    print(f"\n[DEBUG] Total raw nodes fetched from all subs: {len(raw_nodes)}")
    return list(set(raw_nodes))

def convert_node(node_link, target_format):
    try:
        # افزایش تایم اوت به 15 ثانیه
        cmd = ["./subconverter/subconverter", "-g", "--generate-mode", "single", "--url", node_link, "--target", target_format]
        res = subprocess.check_output(cmd, stderr=subprocess.PIPE, timeout=15)
        return res.decode("utf-8")
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Subconverter failed for {node_link[:30]}... Error: {e.stderr.decode('utf-8', errors='ignore')}")
        return None
    except subprocess.TimeoutExpired:
        print(f"[ERROR] Subconverter timeout for {node_link[:30]}...")
        return None
    except Exception as e:
        print(f"[ERROR] Subconverter unexpected error: {e}")
        return None

def test_single_node(node_info):
    index, node_link = node_info
    port_proxy = 10800 + (index % 1000)
    
    print(f"[TEST] Testing node {index}: {node_link[:50]}...")
    
    json_str = convert_node(node_link, "v2ray")
    if not json_str:
        print(f"[TEST] Node {index} failed: Subconverter returned empty.")
        return node_link, 0.0
        
    try:
        outbound_config = json.loads(json_str)
    except Exception as e:
        print(f"[TEST] Node {index} failed: Invalid JSON from Subconverter. {e}")
        return node_link, 0.0

    config_filename = f"temp_xray_{port_proxy}.json"
    full_config = {
        "log": {"loglevel": "none"},
        "inbounds": [{"port": port_proxy, "listen": "127.0.0.1", "protocol": "socks", "settings": {"udp": True}}],
        "outbounds": [outbound_config],
    }
    with open(config_filename, "w", encoding="utf-8") as f:
        json.dump(full_config, f)

    proc = subprocess.Popen(["./xray", "run", "-c", config_filename], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1.5) # افزایش زمان انتظار به 1.5 ثانیه
    
    proxies = {"http": f"socks5h://127.0.0.1:{port_proxy}", "https": f"socks5h://127.0.0.1:{port_proxy}"}
    score = 0.0
    
    try:
        t0 = time.time()
        # افزایش تایم اوت درخواست به 6 ثانیه
        res = requests.get(TEST_URL, proxies=proxies, timeout=6)
        if res.status_code in [200, 204]:
            latency = time.time() - t0
            score = max(1.0, 10.0 - latency)
            print(f"[TEST] Node {index} SUCCESS! Latency: {latency:.2f}s | Score: {score:.2f}")
        else:
            print(f"[TEST] Node {index} failed: HTTP {res.status_code}")
    except Exception as e:
        print(f"[TEST] Node {index} failed: Request error - {e}")
    finally:
        proc.terminate()
        proc.wait()
        if os.path.exists(config_filename):
            os.remove(config_filename)
            
    return node_link, score

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
        print(f"\n{'='*50}")
        print(f"--- پردازش پروفایل: {prof_name} ---")
        print(f"{'='*50}")
        
        personal_nodes = prof_data.get("personal", [])
        sub_urls = prof_data.get("subs", [])
        top_count = prof_data.get("top_count", 20)
        brand_name = prof_data.get("brand_name", "ArsenVPN")
        total_gb = prof_data.get("total_gb", 50)
        expire_days = prof_data.get("expire_days", 30)

        dynamic_nodes = fetch_and_decode_subs(sub_urls)
        
        if not dynamic_nodes:
            print("[WARNING] No dynamic nodes fetched! Check your sub URLs or GitHub IP block.")
            final_nodes = personal_nodes
        else:
            indexed_nodes = list(enumerate(dynamic_nodes))
            tested_results = []
            
            print(f"\n[INFO] Testing {len(indexed_nodes)} nodes...")
            with ThreadPoolExecutor(max_workers=5) as executor: # کاهش به 5 ترد برای جلوگیری از بلاک شدن
                futures = [executor.submit(test_single_node, item) for item in indexed_nodes]
                for future in as_completed(futures):
                    link, score = future.result()
                    if link and score > 0.5:
                        tested_results.append((link, score))

            print(f"\n[INFO] {len(tested_results)} nodes passed the test successfully.")
            
            if tested_results:
                tested_results.sort(key=lambda x: x[1], reverse=True)
                best_dynamic = [x[0] for x in tested_results[:top_count]]
            else:
                best_dynamic = []

            renamed_dynamic = []
            for idx, node in enumerate(best_dynamic, start=1):
                # فعلا بدون تشخیص کشور، فقط شماره گذاری
                custom_title = f"🌐 {brand_name} - {idx:02d}"
                renamed_dynamic.append(rename_node(node, custom_title))

            final_nodes = personal_nodes + renamed_dynamic

        generate_outputs(prof_name, final_nodes, total_gb, expire_days)

    print("\n🎉 عملیات با موفقیت تمام شد.")

if __name__ == "__main__":
    main()
