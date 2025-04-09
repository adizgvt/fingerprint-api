import traceback
from pyzk.zk.base import ZK

def get_device_users(ip):
    try:
        try:
            conn = ZK(ip, port=4370, timeout=120, password=0, force_udp=False, ommit_ping=False)
            conn.connect()
            conn.disable_device()
        except Exception as e:
            print(str(traceback.format_exc()))
        users = conn.get_users()
        
        user_list = []
        for user in users:
            user_list.append({
                "uid": user.uid,
                "name": user.name,
                "privilege": user.privilege,
                "user_id": user.user_id
            })
            
        conn.enable_device()
        conn.disconnect()
        print(user_list)
        
    except Exception as e:
        print(str(traceback.format_exc()))

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python test.py <ip_address>")
        sys.exit(1)
    ip_address = sys.argv[1]
    get_device_users(ip_address)