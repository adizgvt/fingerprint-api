import traceback
from pyzk.zk.base import ZK
import base64

def backup_device(ip):

    # data = 'Sq9TUzIxAAAD7PAECAUHCc7QAAAb7WkBAAAAgxEhXewwAHQPdgCJAADj1QBRABUPrQBW7HAPrQBrAMsO0+x7AJUOuQBTACDjzACbACEPuACd7GsPoQCyAPEPf+yyAEEP2gBwADXjYgC7ADIPcwC87EAPUgDEAPEPnuzLAE8PdAAKAMPjrQDQALUPgQDZ7C4PMADkAPcPiezlANgP7QAsAEfjmQDxAHEPSQAD7X4OfwAHAU0Oo+wGAWQPbwDPAQPjTQAaARsPhQA27R4OOwA/AdUNnexFAXgPVACMAZXhzgBYAeYP93FB6SZr5ZQikVL3sW7WCL/3+XAD/RyLh3qq71/493RJmX+KaQU6kXvx6u2M7yaMWSmzOi3WlOZl9n6AxNm2/4yD+RfC9S8Xvu1A83F3lY0QDrIbOAWlB1p1hJz68iATZZONgyfoXoSgdX6Awf7s/zETPAYzAH8bDGnmt0sY7xLbBwqTrnVs9UEObfgYERLx5AhxiPokbOXOGp/ceXh2gDfmuRBXHroOtBNEizXoRfOBf0L23pXI+7bzeYuNe2J8KJ1Gh0NrrITuMgPMMwECPR7GwgCB7QLB/cE5BMVrBptOBwB5DvrwfQbscA99eA0AFx+FLvxpc8FtA8XYJ+X8EAAyLvD9VUAsN/4EAFkysncM7Cs76f7//jpkRxJLDAB6TAabwEWJDwDQTpDAssCHiMMDANhPDDkRA8VR6Tf/NkP3SQTsZVN0dMT/yQBvuPxARP9DA8XXVvv+CQBkWW0FwIhoDgC5aYn/BHzHi2bBAwCwbNbAF+z1dJrAwXK7kPwtgYMEANR831ki7MiXlsH+k0eAwy2TwIjAdXcHjhvsvZgg//79OsD+E1Y9Mf3+MTsKAz2bF/0zwf6BCwOVnHHEw8PFBJLG6wHOnyLA/TowAOwQrkz/BgBFsBUV+v3zIwEDc6TDmcFlicHDwUHAh5LCacGEwQPFfbTd/BYA27k0Bf3800r/M//9wDj/VMwB97mtwouud8AtwcT/wsHBBMHCZYXBfQkAYgYwjijGxsQGALcBQPzdCQCcxrrDAMfHKsYGAFLJNwfCkvgBr83AxJsGwccvwsLCwsPDBMPDKQkArNRMOzv9+e8ADtot/ArFRNzcw8DEwMDFaSQDw+HA/8D8Ozr+/RIyKf/9O/76wfwQ/Pz+/zUDxQfgrMATAC3oOgZrwC7Bwo7DwpAFLwPY6TB1i8KoTmyLL8COkZbDwgfAwS/AwsLBwMMAxMH2AertRv9EOv3D3MH9MMD//jo+QOcB8e09MU/wBRMGNlxABBDy+GBP7xH/RHDDA9XbWZzBUkIAC0PEAAPnRFI='
    # decoded = base64.b64decode(data).hex()
    # encoded = base64.b64encode(bytes.fromhex(decoded)).decode('utf-8')
    # return decoded

    try:
        try:
            conn = ZK(ip, port=4370, timeout=120, password=0, force_udp=False, ommit_ping=False)
            conn.connect()
            conn.disable_device()
        except Exception as e:
            return {"error": str(traceback.format_exc())}, 500

        users = conn.get_users()
        temps = conn.get_templates()

        # Step 1: Create a dictionary for templates, keyed by user_id (or uid)
        templates_by_user = {}
        for temp in temps:
            if temp.uid not in templates_by_user:
                templates_by_user[temp.uid] = []
            templates_by_user[temp.uid].append({
                "finger_id": int(temp.fid),
                "template": base64.b64encode(temp.template).decode('utf-8')
            })

        # Step 2: Iterate over users and add templates from the dictionary
        users_templates = []
        for user in users:
            user_template = {
                "user": {
                    "user_id": user.user_id,
                    "name": user.name,
                    "privilege": user.privilege,
                    "password": user.password,
                    "group_id": user.group_id,
                    "card": user.card
                },
                "templates": templates_by_user.get(user.uid, [])
            }
            
            users_templates.append(user_template)

        users_templates.sort(key=lambda x: x['user']['user_id'])

        conn.enable_device()
        conn.disconnect()

        return print(users_templates)

    except Exception as e:
        print(f"Error: {traceback.format_exc()}")

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python test.py <ip_address>")
        sys.exit(1)
    ip_address = sys.argv[1]
    backup_device(ip_address)