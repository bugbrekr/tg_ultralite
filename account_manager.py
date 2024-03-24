import database
import hashlib

accountsdb = database.JSONDatabase("db/accountsdb.json")

def create_user(args):
    try:
        username = args[0].strip()
        password = args[1].strip()
    except IndexError:
        return "ERROR\nUsage: createuser <username> <password>"
    if accountsdb.get(username) != None:
        return f"ERROR: Account with username '{username}' already exists."
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    accountsdb[username] = {"password_hash": hashed_password}
    return "Done."

def list_users():
    for account in accountsdb:
        print(account)

def delete_user(args):
    try:
        username = args[0].strip()
    except IndexError:
        return "ERROR\nUsage: delete <username>"
    if accountsdb.get(username) == None:
        return f"ERROR: Account with username '{username}' does not exist."
    accountsdb.pop(username)
    return "Done."

def handler(command, args):
    match command:
        case "create":
            return create_user(args)
        case "list":
            return list_users()
        case "delete":
            return delete_user(args)

while True:
    command = input(">>> ")
    cmd, args = command.split(" ")[0], command.split(" ")[1:]
    resp = handler(cmd, args)
    if resp: print(resp)