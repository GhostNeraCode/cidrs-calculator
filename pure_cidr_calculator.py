#!/usr/bin/env python3
from typing import List, Dict, Union, Tuple

class IP:
    def __init__(self, ip_str: str):
        """Инициализира IP адрес от стринг"""
        self.octets = self._parse_ip(ip_str)
        self.version = 4 if len(self.octets) == 4 else 6
        self.ip_int = self._to_integer()

    def _parse_ip(self, ip_str: str) -> List[int]:
        """Парсва IP адрес от стринг във формат с октети"""
        if '.' in ip_str:  # IPv4
            parts = ip_str.split('.')
            if len(parts) != 4:
                raise ValueError("Невалиден IPv4 адрес")
            return [self._validate_octet(int(p)) for p in parts]
        else:  # IPv6
            raise ValueError("IPv6 все още не се поддържа")

    def _validate_octet(self, octet: int) -> int:
        """Проверява дали октетът е валиден (0-255)"""
        if not (0 <= octet <= 255):
            raise ValueError(f"Невалидна стойност за октет: {octet}")
        return octet

    def _to_integer(self) -> int:
        """Конвертира IP адреса в цяло число"""
        if self.version == 4:
            result = 0
            for octet in self.octets:
                result = (result << 8) + octet
            return result
        return 0  # За IPv6

    def to_binary(self) -> str:
        """Връща IP адреса в двоичен формат"""
        return format(self.ip_int, '032b') if self.version == 4 else format(self.ip_int, '0128b')

    def __str__(self) -> str:
        """Връща IP адреса като стринг"""
        return '.'.join(map(str, self.octets)) if self.version == 4 else ''

    def __lt__(self, other) -> bool:
        return self.ip_int < other.ip_int

    def __le__(self, other) -> bool:
        return self.ip_int <= other.ip_int

    def __eq__(self, other) -> bool:
        return self.ip_int == other.ip_int

class Network:
    def __init__(self, network_str: str):
        """Инициализира мрежа от CIDR нотация"""
        if '/' not in network_str:
            raise ValueError("Липсва префикс в CIDR нотацията")
        
        ip_str, prefix_str = network_str.split('/')
        self.ip = IP(ip_str)
        self.prefix_length = int(prefix_str)
        
        if not (0 <= self.prefix_length <= 32):
            raise ValueError("Невалидна дължина на префикса")
        
        # Изчисляване на мрежова маска
        self.netmask_int = ((1 << 32) - 1) ^ ((1 << (32 - self.prefix_length)) - 1)
        
        # Изчисляване на мрежов адрес
        self.network_address_int = self.ip.ip_int & self.netmask_int
        
        # Изчисляване на broadcast адрес
        self.broadcast_address_int = self.network_address_int | ((1 << (32 - self.prefix_length)) - 1)

    def get_network_address(self) -> str:
        """Връща мрежовия адрес като стринг"""
        return self._int_to_ip_str(self.network_address_int)

    def get_broadcast_address(self) -> str:
        """Връща broadcast адреса като стринг"""
        return self._int_to_ip_str(self.broadcast_address_int)

    def get_netmask(self) -> str:
        """Връща мрежовата маска като стринг"""
        return self._int_to_ip_str(self.netmask_int)

    def get_first_usable(self) -> str:
        """Връща първия използваем IP адрес"""
        return self._int_to_ip_str(self.network_address_int + 1)

    def get_last_usable(self) -> str:
        """Връща последния използваем IP адрес"""
        return self._int_to_ip_str(self.broadcast_address_int - 1)

    def get_num_addresses(self) -> int:
        """Връща броя на адресите в мрежата"""
        return 1 << (32 - self.prefix_length)

    @staticmethod
    def _int_to_ip_str(ip_int: int) -> str:
        """Конвертира IP адрес от цяло число в стринг"""
        octets = []
        for _ in range(4):
            octets.insert(0, str(ip_int & 255))
            ip_int >>= 8
        return '.'.join(octets)

def find_optimal_cidrs(start_ip_str: str, end_ip_str: str) -> List[str]:
    """Намира оптималните CIDR блокове между два IP адреса"""
    try:
        start_ip = IP(start_ip_str)
        end_ip = IP(end_ip_str)

        if start_ip.version != end_ip.version:
            raise ValueError("IP адресите трябва да са от един и същ тип")

        if start_ip > end_ip:
            start_ip, end_ip = end_ip, start_ip

        result = []
        while start_ip <= end_ip:
            max_prefix = 32
            for prefix in range(32, -1, -1):
                network = Network(f"{str(start_ip)}/{prefix}")
                broadcast_ip = IP(network.get_broadcast_address())
                if broadcast_ip <= end_ip:
                    max_prefix = prefix
                    break

            network = Network(f"{str(start_ip)}/{max_prefix}")
            result.append(f"{str(start_ip)}/{max_prefix}")
            broadcast_ip = IP(network.get_broadcast_address())
            start_ip = IP(Network._int_to_ip_str(broadcast_ip.ip_int + 1))

        return result
    except ValueError as e:
        return [f"Грешка: {str(e)}"]

def print_banner():
    """Отпечатва банер на програмата"""
    print("\033[95m")  # Лилав цвят
    print("╔═════════════════════════════════════════════════╗")
    print("║             PURE CIDR КАЛКУЛАТОР               ║")
    print("║            Без Външни Библиотеки              ║")
    print("║               Made by Ivansky                  ║")
    print("╚═════════════════════════════════════════════════╝")
    print("\033[0m")

def analyze_network(cidr: str) -> Dict[str, Union[str, int]]:
    """Анализира CIDR нотация и връща информация за мрежата"""
    try:
        network = Network(cidr)
        return {
            "Мрежов адрес": network.get_network_address(),
            "Broadcast адрес": network.get_broadcast_address(),
            "Мрежова маска": network.get_netmask(),
            "Префикс": network.prefix_length,
            "Брой адреси": network.get_num_addresses(),
            "Първи използваем": network.get_first_usable(),
            "Последен използваем": network.get_last_usable(),
            "Маска (двоично)": format(network.netmask_int, '032b')
        }
    except ValueError as e:
        return {"error": str(e)}

def main():
    print_banner()

    while True:
        print("\n\033[94mИзберете опция:\033[0m")
        print("1. Анализ на CIDR нотация")
        print("2. Намиране на оптимални CIDR блокове")
        print("3. Изход")

        choice = input("\nВашият избор (1-3): ").strip()

        if choice == "3":
            print("\n\033[95mДовиждане! Made by Ivansky\033[0m")
            break

        elif choice == "1":
            cidr = input("\nВъведете CIDR нотация (пр. 192.168.1.0/24): ").strip()
            info = analyze_network(cidr)
            
            if "error" in info:
                print(f"\n\033[91mГрешка: {info['error']}\033[0m")
                continue

            print("\n\033[92mИнформация за мрежата:\033[0m")
            print("-" * 40)
            for key, value in info.items():
                print(f"\033[96m{key}:\033[0m {value}")

        elif choice == "2":
            start_ip = input("\nВъведете начален IP адрес: ").strip()
            end_ip = input("Въведете краен IP адрес: ").strip()
            
            cidrs = find_optimal_cidrs(start_ip, end_ip)
            
            if cidrs and cidrs[0].startswith("Грешка"):
                print(f"\n\033[91m{cidrs[0]}\033[0m")
                continue

            print("\n\033[92mОптимални CIDR блокове:\033[0m")
            print("-" * 40)
            
            for i, cidr in enumerate(cidrs, 1):
                print(f"\n\033[96mБлок {i}:\033[0m")
                info = analyze_network(cidr)
                print(f"CIDR: {cidr}")
                print(f"Мрежов адрес: {info['Мрежов адрес']}")
                print(f"Broadcast адрес: {info['Broadcast адрес']}")
                print(f"Брой адреси: {info['Брой адреси']}")
                print(f"Първи използваем: {info['Първи използваем']}")
                print(f"Последен използваем: {info['Последен използваем']}")

        else:
            print("\n\033[91mНевалиден избор. Моля, изберете 1, 2 или 3.\033[0m")

if __name__ == "__main__":
    main() 