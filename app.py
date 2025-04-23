from flask import Flask, request, Response, jsonify
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity

import sys
import os
import json
import re
import traceback
import base64
import time
import hashlib
sys.path.insert(1,os.path.abspath("./pyzk"))
from zk import ZK, const
from zk.finger import Finger


app                             = Flask(__name__)
#-------------------------------------------------------------------------------------
app.config["JWT_SECRET_KEY"]    = "your_secret_key"  # Change this to a secure key
app.config["DEBUG"]             = True  # Enable debug mode

jwt                             = JWTManager(app)
#-------------------------------------------------------------------------------------

# Fake user database
users = {"admin": "161ebd7d45089b3446ee4e0d86dbcf92"}



def register_fingerprint(user_id, fid, template, conn):
    try:
        finger = Finger(
            uid=user_id, 
            fid=fid, 
            valid=1, 
            template=bytes.fromhex(template)
        )

        conn.save_user_template(user_id, [finger])

        return True, None

    except Exception as e:
        return False, str(traceback.format_exc())

def create_user(ujer_id, ujer_name, ujer_privilege, ujer_password, ujer_group_id, ujer_card, conn):
    try:
        conn.set_user(
            name=ujer_name, 
            privilege=ujer_privilege, 
            password=ujer_password, 
            group_id=ujer_group_id,
            card=ujer_card,
            user_id=str(ujer_id)
        )
        return True, None

    except Exception as e:
        traceback.print_exc()
        return False, str(traceback.format_exc())

def delete_user(user_id, conn):
    try:
        conn.delete_user(user_id=user_id)
        return True, None
    except Exception as e:
        return False, str(traceback.format_exc())

@app.route("/api/login", methods=["POST"])
def login():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    if username in users and hashlib.md5(password.encode()).hexdigest() == users[username]:
        access_token = create_access_token(identity=username)
        return jsonify(access_token=access_token)

    return jsonify({"msg": "Invalid credentials"}), 401


@app.route("/")
def home():
    return "Hello, Flask!"

@app.route("/api/devices")
@jwt_required()
def get_devices():
    #todo: get devices from database
    return [
        {
            "name": "Device 1",
            "ip": "192.168.1.33",
        },
        {
            "name": "Device 2",
            "ip": "192.168.1.35",
        }
    ]

@app.route("/api/device/<ip>/users")
@jwt_required()
def get_device_users(ip):
    try:
        try:
            conn = ZK(ip, port=4370, timeout=120, password=0, force_udp=True, ommit_ping=False)
            conn.connect()
            conn.disable_device()
        except Exception as e:
            return {"error": str(e)}, 500
        
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
        return user_list
        
    except Exception as e:
        return {"error": str(traceback.format_exc())}, 500


# @app.route("/api/copy_users", methods=["POST"])
# def copy_users():
#     data            = request.json
#     source_ip       = data.get("source_ip")
#     target_ip       = data.get("target_ip")
#     user_list       = data.get("user_list")

#     if not request.is_json:
#         return {"error": "Content-Type must be application/json"}, 400

#     required_fields = ["source_ip", "target_ip", "user_list"]
#     for field in required_fields:
#         if field not in data:
#             return {"error": f"Missing required field: {field}"}, 400

#     sourceConn      = None
#     targetConn      = None

#     users_found     = []
#     missing_users   = []
#     user_templates  = []
#     results         = []

#     if not isinstance(user_list, list) or not all(isinstance(item, str) for item in user_list):
#         return {"error": "user_list must be a list of strings"}, 500

#     if not source_ip or not target_ip:
#         return {"error": "source_ip and target_ip are required"}, 400

#     ip_pattern = r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$'
#     if not re.match(ip_pattern, source_ip) or not re.match(ip_pattern, target_ip):
#         return {"error": "Invalid IP address format"}, 400

#     # device_ips = [d["ip"] for d in get_devices()]
#     # if source_ip not in device_ips or target_ip not in device_ips:
#     #     return {"error": "Source or target IP not found in device list"}, 404


#     try:
#         try:
#             zkSource = ZK(source_ip, port=4370, timeout=5, password=0, force_udp=True, ommit_ping=False)
#             sourceConn = zkSource.connect()
#         except Exception as e:
#             return {"error": f"Failed to connect to source device: {str(e)}"}, 500

#         sourceConn.disable_device()

#         source_users = sourceConn.get_users()
#         for user in source_users:

#             privilege = 'Admin' if user.privilege == const.USER_ADMIN else 'User'

#             if(user.user_id in user_list):
#                 # print('+ UID #{}'.format(user.uid))
#                 # print('  Name       : {}'.format(user.name))
#                 # print('  Privilege  : {}'.format(privilege))
#                 # print('  Password   : {}'.format(user.password))
#                 # print('  Group ID   : {}'.format(user.group_id))
#                 # print('  User  ID   : {}'.format(user.user_id))
#                 users_found.append(user)


#         if(len(users_found) == 0):
#             return {"error": f"No users found from source"}, 500

#         if(len(users_found) != len(user_list)):
#             print("NOT ALL USERS FOUND")
#             missing_users = [uid for uid in user_list if uid not in [u.user_id for u in users_found]]
#             print('MISSING USER IDS: ' + ', '.join(missing_users))

#         fingerprint_templates = sourceConn.get_templates()

#         for t in fingerprint_templates:
#             if(t.uid in [u.uid for u in users_found] and t.valid == 1):
#                 print(f"UID {t.uid} corresponds to User ID {next(u.user_id for u in users_found if u.uid == t.uid)}")    
                
#                 data = {
#                     "user_id": next(u.user_id for u in users_found if u.uid == t.uid),
#                     "name": next(u.name for u in users_found if u.uid == t.uid),
#                     "finger_id": t.fid,
#                     "template": t.template.hex(),
#                 }

#                 user_templates.append(data)
                


#         print('FOUND TEMPLATES:')
#         print(user_templates)

#         if(len(user_templates) == 0):
#             return {"error": f"No templates found"}, 500

#         sourceConn.enable_device()

#         #--------------------------------
#         #       WRITE TEMPLATES
#         #--------------------------------

#         try:
#             zkTarget = ZK(target_ip, port=4370, timeout=5, password=0, force_udp=True, ommit_ping=False)
#             targetConn = zkTarget.connect()
#         except Exception as e:
#             return {"error": f"Failed to connect to target device: {str(e)}"}, 500

#         targetConn.disable_device()
#         target_users = targetConn.get_users()

#         print("Target users:")
#         for user in target_users:
#             print(f"User ID: {user}")

#         for t in user_templates:

#             #IF USER DOES NOT EXIST, CREATE IT FIRST
#             if(t['user_id'] not in [u.user_id for u in target_users]):

#                 print(f"User {t['user_id']} does not exist")

#                 status, error_msg = create_user(
#                     t['user_id'], 
#                     t['name'], 
#                     targetConn
#                 )

#                 if(status):
#                     print(f"User {t['user_id']} created")
#                     results.append(
#                         {
#                             "user_id": t['user_id'], 
#                             "status": "success",
#                             "message": f"User {t['user_id']} created",
#                             "source": source_ip,
#                             "target": target_ip
#                         }
#                     )
#                 else:
#                     print(f"Failed to create user {t['user_id']}: {error_msg}")
#                     results.append(
#                         {
#                             "user_id": t['user_id'], 
#                             "status": "error", 
#                             "message": f"Failed to create user {t['user_id']}: {error_msg}",
#                             "source": source_ip,
#                             "target": target_ip
#                         }
#                     )
#                 continue

#             #CHECK IF NAME NEEDS TO BE UPDATED
#             current_user = next(u for u in target_users if u.user_id == t['user_id'])
#             if current_user.name != t['name']:

#                 delete_status, delete_error_msg = delete_user(t['user_id'], targetConn)
#                 if(delete_status):
#                     print(f"User {t['user_id']} deleted")

#                     status, error_msg = create_user(
#                         t['user_id'], 
#                         t['name'], 
#                         targetConn
#                     )   

#                     if(status):
#                         print(f"User {t['user_id']} created")
#                         results.append(
#                             {
#                                 "user_id": t['user_id'], 
#                                 "status": "success", 
#                                 "message": f"User {t['user_id']} re-created",
#                             }
#                         )
#                     else:
#                         print(f"Failed to create user {t['user_id']}: {error_msg}") 
#                         results.append(
#                             {
#                                 "user_id": t['user_id'], 
#                                 "status": "error", 
#                                 "message": f"Failed to create user {t['user_id']}: {error_msg}",
#                             }
#                         )   

#                 else:
#                     print(f"Failed to delete user {t['user_id']}: {delete_error_msg}")
#                     results.append(
#                         {
#                             "user_id": t['user_id'], 
#                             "status": "error", 
#                             "message": f"Failed to delete user {t['user_id']}: {delete_error_msg}",
#                         }
#                     )
#                     continue
                
            
#             #REGISTER FINGERPRINT
#             status, error_msg = register_fingerprint(
#                 t['user_id'], 
#                 t['finger_id'], 
#                 t['template'], 
#                 targetConn
#             )
#             if(status):
#                 print(f"Fingerprint registered for user {t['user_id']}")
#                 results.append(
#                     {
#                         "user_id": t['user_id'], 
#                         "status": "success", 
#                         "message": f"Fingerprint registered for user {t['user_id']}",
#                         "source": source_ip,
#                         "target": target_ip
#                     }
#                 )
#             else:
#                 print(f"Failed to register fingerprint for user {t['user_id']}: {error_msg}")
#                 results.append(
#                     {
#                         "user_id": t['user_id'], 
#                         "status": "error", 
#                         "message": f"Failed to register fingerprint for user {t['user_id']}: {error_msg}",
#                         "source": source_ip,
#                         "target": target_ip
#                     }
#                 )
        
#         targetConn.enable_device();

#         if sourceConn:
#             sourceConn.disconnect()

#         if targetConn:
#             targetConn.disconnect()

#         return jsonify(results)

#     except Exception as e:
#         traceback.print_exc()
#         return {"error": str(e)}, 500


@app.route("/api/device/<ip>/backup", methods=['GET'])
@jwt_required()
def backup_device(ip):

    # data = 'Sq9TUzIxAAAD7PAECAUHCc7QAAAb7WkBAAAAgxEhXewwAHQPdgCJAADj1QBRABUPrQBW7HAPrQBrAMsO0+x7AJUOuQBTACDjzACbACEPuACd7GsPoQCyAPEPf+yyAEEP2gBwADXjYgC7ADIPcwC87EAPUgDEAPEPnuzLAE8PdAAKAMPjrQDQALUPgQDZ7C4PMADkAPcPiezlANgP7QAsAEfjmQDxAHEPSQAD7X4OfwAHAU0Oo+wGAWQPbwDPAQPjTQAaARsPhQA27R4OOwA/AdUNnexFAXgPVACMAZXhzgBYAeYP93FB6SZr5ZQikVL3sW7WCL/3+XAD/RyLh3qq71/493RJmX+KaQU6kXvx6u2M7yaMWSmzOi3WlOZl9n6AxNm2/4yD+RfC9S8Xvu1A83F3lY0QDrIbOAWlB1p1hJz68iATZZONgyfoXoSgdX6Awf7s/zETPAYzAH8bDGnmt0sY7xLbBwqTrnVs9UEObfgYERLx5AhxiPokbOXOGp/ceXh2gDfmuRBXHroOtBNEizXoRfOBf0L23pXI+7bzeYuNe2J8KJ1Gh0NrrITuMgPMMwECPR7GwgCB7QLB/cE5BMVrBptOBwB5DvrwfQbscA99eA0AFx+FLvxpc8FtA8XYJ+X8EAAyLvD9VUAsN/4EAFkysncM7Cs76f7//jpkRxJLDAB6TAabwEWJDwDQTpDAssCHiMMDANhPDDkRA8VR6Tf/NkP3SQTsZVN0dMT/yQBvuPxARP9DA8XXVvv+CQBkWW0FwIhoDgC5aYn/BHzHi2bBAwCwbNbAF+z1dJrAwXK7kPwtgYMEANR831ki7MiXlsH+k0eAwy2TwIjAdXcHjhvsvZgg//79OsD+E1Y9Mf3+MTsKAz2bF/0zwf6BCwOVnHHEw8PFBJLG6wHOnyLA/TowAOwQrkz/BgBFsBUV+v3zIwEDc6TDmcFlicHDwUHAh5LCacGEwQPFfbTd/BYA27k0Bf3800r/M//9wDj/VMwB97mtwouud8AtwcT/wsHBBMHCZYXBfQkAYgYwjijGxsQGALcBQPzdCQCcxrrDAMfHKsYGAFLJNwfCkvgBr83AxJsGwccvwsLCwsPDBMPDKQkArNRMOzv9+e8ADtot/ArFRNzcw8DEwMDFaSQDw+HA/8D8Ozr+/RIyKf/9O/76wfwQ/Pz+/zUDxQfgrMATAC3oOgZrwC7Bwo7DwpAFLwPY6TB1i8KoTmyLL8COkZbDwgfAwS/AwsLBwMMAxMH2AertRv9EOv3D3MH9MMD//jo+QOcB8e09MU/wBRMGNlxABBDy+GBP7xH/RHDDA9XbWZzBUkIAC0PEAAPnRFI='
    # decoded = base64.b64decode(data).hex()
    # encoded = base64.b64encode(bytes.fromhex(decoded)).decode('utf-8')
    # return decoded

    try:
        try:
            conn = ZK(ip, port=4370, timeout=120, password=0, force_udp=True, ommit_ping=False)
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
                user.user_id: {
                    "uid": user.uid,
                    "user_id": user.user_id,
                    "name": user.name,
                    "privilege": user.privilege,
                    "password": user.password,
                    "group_id": user.group_id,
                    "card": user.card,
                    "templates": templates_by_user.get(user.uid, [])
                },
            }
            
            users_templates.append(user_template)

        # users_templates.sort(key=lambda x: x['user']['user_id'])

        conn.enable_device()
        conn.disconnect()

        return jsonify(users_templates)

    except Exception as e:
        print(f"Error: {traceback.format_exc()}")
        return {"error": str(traceback.format_exc())}, 500

@app.route("/api/device/<ip>/backup/fingerprint/<uid>", methods=['GET'])
@jwt_required()
def backup_fingerprint(ip, uid):

    try:
        try:
            conn = ZK(ip, port=4370, timeout=120, password=0, force_udp=True, ommit_ping=False, verbose=True)
            conn.connect()
            conn.disable_device()
        except Exception as e:
            return {"error": str(traceback.format_exc())}, 500

        temps = []
        for temp_id in range(10):
            temp = conn.get_user_template(uid=int(uid), temp_id=temp_id)
            if temp:
                temps.append(temp)

        fingerprints = []
        for temp in temps:
            fingerprints.append({
                "finger_id": int(temp.fid),
                "template": base64.b64encode(temp.template).decode('utf-8')
            })
        

        conn.enable_device()
        conn.disconnect()

        return jsonify(fingerprints)

    except Exception as e:
        return {"error": traceback.format_exc()}, 500
        # print(f"Error: {traceback.format_exc()}")


@app.route("/api/device/<ip>/restore/user", methods=['POST'])
@jwt_required()
def restore_device(ip):
    data = request.json

    # Sample request data:
    # [
    #     {
    #         "user": {
    #             "name": "John Smith",
    #             "privilege": 0,
    #             "user_id": "123"
    #             "password": "password123",
    #             "group_id": "1",
    #             "card": "1234567890"
    #         },
    #         "templates": [
    #             {
    #                 "finger_id": 6,
    #                 "template": "base64EncodedTemplateString..."
    #             }
    #         ]
    #     }
    # ]

    if not isinstance(data, list):
        return {"error": "Data must be a list"}, 400

    for item in data:
        if not isinstance(item, dict):
            return {"error": "Each item must be an object"}, 400
            
        if "user" not in item or "templates" not in item:
            return {"error": "Each item must have 'user' and 'templates' fields"}, 400
            
        user = item["user"]
        if not all(field in user for field in ["name", "privilege", "user_id", "password", "group_id", "card"]):
            return {"error": "User object must have name, privilege, user_id, password, group_id and card fields"}, 400
            
        templates = item["templates"]
        if not isinstance(templates, list):
            return {"error": "Templates must be a list"}, 400
            
        for template in templates:
            if not all(field in template for field in ["finger_id", "template"]):
                return {"error": "Each template must have finger_id and template fields"}, 400

    try:
        try:
            conn = ZK(ip, port=4370, timeout=120, password=0, force_udp=True, ommit_ping=False)
            conn.connect()
        except Exception as e:
            return {"error": str(traceback.format_exc())}, 500

        users = conn.get_users()

        results = []

        for datum in data:

            user_data = datum["user"]
            templates = datum["templates"]
            
            #CREATE IF USER DOES NOT EXIST
            if(user_data['user_id'] not in [u.user_id for u in users]):

                print(f"User {user_data['user_id']} does not exist")

                status, error_msg = create_user(
                    user_data['user_id'], 
                    user_data['name'], 
                    user_data['privilege'],
                    user_data['password'],
                    user_data['group_id'],
                    user_data['card'],
                    conn
                )

                if(status):
                    print(f"User {user_data['user_id']} created")
                    results.append(
                        {
                            "user_id"   : user_data['user_id'], 
                            "name"      : user_data['name'],
                            "status"    : "success",
                            "message"   : f"User {user_data['user_id']} created",
                        }
                    )

                else:
                    print(f"Failed to create user {user_data['user_id']}: {error_msg}")
                    results.append(
                        {
                            "user_id"   : user_data['user_id'], 
                            "name"      : user_data['name'],
                            "status"    : "error", 
                            "message"   : f"Failed to create user {user_data['user_id']}: {error_msg}",
                        }
                    )
                continue

            #CHECK IF NAME NEEDS TO BE UPDATED
            current_user = next(u for u in users if u.user_id == user_data['user_id'])

            if current_user.name != user_data['name']:

                delete_status, delete_error_msg = delete_user(user_data['user_id'], conn)
                if(delete_status):
                    print(f"User {user_data['user_id']} deleted")

                    status, error_msg = create_user(
                        user_data['user_id'], 
                        user_data['name'], 
                        user_data['privilege'],
                        user_data['password'],
                        user_data['group_id'],
                        user_data['card'],
                        conn
                    )   

                    if(status):
                        print(f"User {user_data['user_id']} created")
                        results.append(
                            {
                                "user_id"   : user_data['user_id'], 
                                "name"      : user_data['name'],
                                "status"    : "success", 
                                "message"   : f"User {user_data['user_id']} re-created",
                            }
                        )
                    else:
                        print(f"Failed to create user {user_data['user_id']}: {error_msg}") 
                        results.append(
                            {
                                "user_id"   : template['user_id'], 
                                "name"      : template['name'],
                                "status"    : "error", 
                                "message"   : f"Failed to create user {user_data['user_id']}: {error_msg}",
                            }
                        )
                        continue

                else:
                    print(f"Failed to delete user {user_data['user_id']}: {delete_error_msg}")
                    results.append(
                        {
                            "user_id"   : template['user_id'], 
                            "name"      : template['name'],
                            "status"    : "error", 
                            "message"   : f"Failed to delete existing user {user_data['user_id']}: {delete_error_msg}",
                        }
                    )
                    continue
            
            #REGISTER FINGERPRINT
            for template in datum['templates']:
                status, error_msg = register_fingerprint(
                    user_data['user_id'], 
                    template['finger_id'], 
                    base64.b64decode(template['template']).hex(), 
                    conn
                )
                if(status):
                    print(f"Fingerprint registered for user {user_data['user_id']}")
                    results.append(
                        {
                            "user_id"   : user_data['user_id'], 
                            "name"      : user_data['name'],
                            "status"    : "success", 
                            "message"   : f"Fingerprint registered for user {user_data['user_id']}",
                        }
                    )
                else:
                    print(f"Failed to register fingerprint for user {user_data['user_id']}: {error_msg}")
                    results.append(
                        {
                            "user_id"   : user_data['user_id'], 
                            "name"      : user_data['name'],
                            "status"    : "error", 
                            "message"   : f"Failed to register fingerprint for user {user_data['user_id']}: {error_msg}",
                        }
                    )

            

        return jsonify(results)

    except Exception as e:
        print(f"Error: {e}")
        traceback.print_exc() 
        return {"error": str(traceback.format_exc())}, 500

@app.route("/api/device/<ip>/restore/fingerprints", methods=['POST'])
@jwt_required()
def restore_fingerprints(ip):
    try:
        # Connect to device
        try:
            conn = ZK(ip, port=4370, timeout=120, password=0, force_udp=True, ommit_ping=False)
            conn.connect()
            conn.disable_device()
        except Exception as e:
            return {"error": str(traceback.format_exc())}, 500

        # Get request data
        data = request.get_json()

        results = []

        if not isinstance(data, list):
            return {"error": "Data must be a list"}, 400

        for item in data:
            if not isinstance(item, dict):
                return {"error": "Each item must be an object"}, 400
            
        if "user" not in item or "templates" not in item:
            return {"error": "Each item must have 'user' and 'templates' fields"}, 400
            
        user = item["user"]
        if not all(field in user for field in ["user_id"]):
            return {"error": "User object must have user_id fields"}, 400
            
        templates = item["templates"]
        if not isinstance(templates, list):
            return {"error": "Templates must be a list"}, 400
            
        for template in templates:
            if not all(field in template for field in ["finger_id", "template"]):
                return {"error": "Each template must have finger_id and template fields"}, 400

        # Process each user's fingerprint templates
        for datum in data:
            user_data = datum['user']
            
            # Register fingerprints for user
            for template in datum['templates']:
                status, error_msg = register_fingerprint(
                    user_data['user_id'],
                    template['finger_id'],
                    base64.b64decode(template['template']).hex(),
                    conn
                )
                
                if status:
                    print(f"Fingerprint registered for user {user_data['user_id']}")
                    results.append({
                        "user_id": user_data['user_id'],
                        "status": "success",
                        "message": f"Fingerprint registered for user {user_data['user_id']}"
                    })
                else:
                    print(f"Failed to register fingerprint for user {user_data['user_id']}: {error_msg}")
                    results.append({
                        "user_id": user_data['user_id'],
                        "status": "error", 
                        "message": f"Failed to register fingerprint for user {user_data['user_id']}: {error_msg}"
                    })

        return jsonify(results)

    except Exception as e:
        traceback.print_exc()
        return {"error": traceback.format_exc()}, 500

@app.route("/api/device/<ip>/attendance/all", methods=['GET'])
def get_all_attendance(ip):
    try:
        return _get_attendance(ip)
    except Exception as e:
        print(str(traceback.format_exc()))
        return []

@app.route("/api/device/<ip>/attendance/user/<user_id>", methods=['GET'])
def get_attendance_by_user(ip, user_id):
    try:
        return _get_attendance(ip, user_id=user_id)
    except Exception as e:
        print(str(traceback.format_exc()))
        return []

@app.route("/api/device/<ip>/attendance/date/<start_date>/<end_date>", methods=['GET'])
def get_attendance_by_date(ip, start_date, end_date):
    try:
        return _get_attendance(ip, start_date=start_date, end_date=end_date)
    except Exception as e:
        print(str(traceback.format_exc()))
        return []



def _get_attendance(ip, user_id=None, start_date=None, end_date=None):
    try:
        try:
            conn = ZK(ip, port=4370, timeout=120, password=0, force_udp=False, ommit_ping=False)
            conn.connect()
            conn.disable_device()
        except Exception as e:
            print(str(traceback.format_exc()))
            
        inicio = time.time()
        attendance = conn.get_attendance()
        final = time.time()
        
        attendance_list = []
        for att in attendance:
            # Convert timestamp string to datetime for comparison
            att_timestamp = att.timestamp
            
            print(att_timestamp)
            # Apply filters
            if user_id and str(att.user_id) != str(user_id):
                continue
                
            if  att_timestamp < start_date:
                print(att_timestamp, 'less than', start_date)
                continue
                
            if att_timestamp > end_date:
                print(att_timestamp, 'greater than', end_date)
                continue
                
            attendance_list.append({
                "uid": att.uid,
                "user_id": att.user_id,
                "timestamp": str(att_timestamp),
                "status": att.status,
                "punch": att.punch
            })
            
        conn.enable_device()
        conn.disconnect()

        return attendance_list
        
    except Exception as e:
        print(str(traceback.format_exc()))


# def stream_logs():
#     for i in range(20):
#         yield f"Log entry #{i}: Processing data batch {i*10} to {(i+1)*10}\n"
#         yield f"Status: Running verification checks...\n" 
#         #time.sleep(1)
#         yield f"Memory usage: {50 + i*2}MB\n"
#         yield f"Active connections: {3 + (i % 5)}\n"
#         #time.sleep(1)
#         yield f"Completed batch {i} successfully\n"
#         yield "----------------------------------------\n"
#         time.sleep(2)  # Simulate log processing delay



if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)