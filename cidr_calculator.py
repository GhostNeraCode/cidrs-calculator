#!/usr/bin/env python3
import ipaddress
from typing import List

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

def calculate_optimal_cidrs(start_ip: str, end_ip: str) -> List[str]:
    """
    Изчислява оптималните CIDR блокове между два IP адреса
    """
    try:
        start = ipaddress.ip_address(start_ip)
        end = ipaddress.ip_address(end_ip)
        
        if start.version != end.version:
            raise ValueError("Start IP и End IP трябва да са от един и същ тип (IPv4 или IPv6)")
        
        if start > end:
            start, end = end, start
            
        networks = [str(net) for net in ipaddress.summarize_address_range(start, end)]
        return networks
    except ValueError as e:
        return [f"Грешка: {str(e)}"]

def main():
    print("CIDR Калкулатор (IPv4 и IPv6)")
    print("-" * 50)
    
    while True:
        print("\nИзберете режим:")
        print("1. Анализ на CIDR нотация")
        print("2. Намиране на оптимални CIDR блокове между два IP адреса")
        print("3. Изход")
        
        choice = input("\nВашият избор (1-3): ")
        
        if choice == "3":
            break
            
        if choice == "1":
            cidr = input("\nВъведете CIDR нотация (например 192.168.1.0/24 или 2001:db8::/32): ")
            if not cidr:
                continue
                
            result = analyze_network(cidr)
            
            if "Грешка" in result:
                print(f"\nГрешка: {result['Грешка']}")
                continue
                
            print("\nРезултати:")
            print("-" * 20)
            for key, value in result.items():
                print(f"{key}: {value}")
                
        elif choice == "2":
            start_ip = input("\nВъведете начален IP адрес: ")
            end_ip = input("Въведете краен IP адрес: ")
            
            cidrs = calculate_optimal_cidrs(start_ip, end_ip)
            
            print("\nОптимални CIDR блокове:")
            print("-" * 20)
            if cidrs and cidrs[0].startswith("Грешка"):
                print(cidrs[0])
            else:
                for i, cidr in enumerate(cidrs, 1):
                    print(f"{i}. {cidr}")
                    result = analyze_network(cidr)
                    if "Грешка" not in result:
                        print(f"   Брой адреси: {result['Брой адреси']}")
                        print(f"   Start IP: {result['Start IP']}")
                        print(f"   End IP: {result['End IP']}")
                        print()
        else:
            print("\nНевалиден избор. Моля, изберете 1, 2 или 3.")

if __name__ == "__main__":
    main() 