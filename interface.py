from scapy.all import get_if_list

def choose_interface():
    interfaces = get_if_list()

    print("\nAvailable Network Interfaces:")
    print("-" * 40)

    for i, iface in enumerate(interfaces, start=1):
        print(f"{i}. {iface}")

    while True:
        try:
            choice = int(input("\nSelect an interface: "))
            if 1 <= choice <= len(interfaces):
                return interfaces[choice - 1]
            else:
                print("Invalid choice. Try again.")
        except ValueError:
            print("Please enter a valid number.")
