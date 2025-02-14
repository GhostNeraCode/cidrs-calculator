#!/usr/bin/env python3
import ipaddress

def analyze_network(cidr_notation):
    """
    Анализира CIDR нотация и връща информация за мрежата
    """
    try:
        network = ipaddress.ip_network(cidr_notation, strict=False)
        
        # Намираме първия и последния IP адрес в мрежата
        start_ip = network[0]
        end_ip = network[-1]
        
        result = {
            "Версия": "IPv6" if network.version == 6 else "IPv4",
            "Мрежов адрес": str(network.network_address),
            "Broadcast адрес": str(network.broadcast_address) if network.version == 4 else "N/A",
            "Маска": str(network.netmask),
            "Префикс дължина": network.prefixlen,
            "Start IP": str(start_ip),
            "End IP": str(end_ip),
            "Брой адреси": network.num_addresses,
            "Първи използваем": str(network[1]) if network.num_addresses > 2 else "N/A",
            "Последен използваем": str(network[-2]) if network.num_addresses > 2 else "N/A"
        }
        
        # Добавяме двоичен формат за IPv4
        if network.version == 4:
            result["Start IP (binary)"] = format(int(start_ip), '032b')
            result["End IP (binary)"] = format(int(end_ip), '032b')
            result["Маска (binary)"] = format(int(network.netmask), '032b')
        
        return result
    except ValueError as e:
        return {"Грешка": str(e)}

def main():
    print("CIDR Калкулатор (IPv4 и IPv6)")
    print("-" * 50)
    
    while True:
        cidr = input("\nВъведете CIDR нотация (например 192.168.1.0/24 или 2001:db8::/32)\n" +
                     "или натиснете Enter за изход: ")
        
        if not cidr:
            break
            
        result = analyze_network(cidr)
        
        if "Грешка" in result:
            print(f"\nГрешка: {result['Грешка']}")
            continue
            
        print("\nРезултати:")
        print("-" * 20)
        for key, value in result.items():
            print(f"{key}: {value}")

if __name__ == "__main__":
    main() 