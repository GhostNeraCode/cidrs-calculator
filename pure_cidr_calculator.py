#!/usr/bin/env python3
from typing import List, Dict, Union, Tuple
import re

class IP:
    def __init__(self, ip_str: str):
        """Инициализира IP адрес от стринг"""
        self.original_str = ip_str
        self.version = 6 if ':' in ip_str else 4
        self.ip_int = self._to_integer(ip_str)

    def _to_integer(self, ip_str: str) -> int:
        """Конвертира IP адрес в цяло число"""
        if self.version == 4:
            return self._ipv4_to_int(ip_str)
        return self._ipv6_to_int(ip_str)

    def _ipv4_to_int(self, ip_str: str) -> int:
        """Конвертира IPv4 адрес в цяло число"""
        parts = ip_str.split('.')
        if len(parts) != 4:
            raise ValueError("Невалиден IPv4 адрес")
        
        result = 0
        for part in parts:
            octet = int(part)
            if not (0 <= octet <= 255):
                raise ValueError(f"Невалидна стойност за октет: {octet}")
            result = (result << 8) + octet
        return result

    def _ipv6_to_int(self, ip_str: str) -> int:
        """Конвертира IPv6 адрес в цяло число"""
        # Разширяване на съкратен IPv6 адрес
        if '::' in ip_str:
            missing_count = 8 - ip_str.count(':') + 1
            ip_str = ip_str.replace('::', ':' + ':0' * missing_count + ':')
            if ip_str.startswith(':'):
                ip_str = '0' + ip_str
            if ip_str.endswith(':'):
                ip_str = ip_str + '0'

        parts = ip_str.split(':')
        if len(parts) != 8:
            raise ValueError("Невалиден IPv6 адрес")

        result = 0
        for part in parts:
            if not part:
                raise ValueError("Невалиден IPv6 адрес")
            hex_val = int(part, 16)
            if not (0 <= hex_val <= 0xFFFF):
                raise ValueError(f"Невалидна стойност за IPv6 част: {part}")
            result = (result << 16) + hex_val
        return result

    def to_binary(self) -> str:
        """Връща IP адреса в двоичен формат"""
        if self.version == 4:
            return format(self.ip_int, '032b')
        return format(self.ip_int, '0128b')

    def __str__(self) -> str:
        """Връща IP адреса като стринг"""
        if self.version == 4:
            return self._int_to_ipv4_str(self.ip_int)
        return self._int_to_ipv6_str(self.ip_int)

    @staticmethod
    def _int_to_ipv4_str(ip_int: int) -> str:
        """Конвертира цяло число в IPv4 стринг"""
        octets = []
        for _ in range(4):
            octets.insert(0, str(ip_int & 255))
            ip_int >>= 8
        return '.'.join(octets)

    @staticmethod
    def _int_to_ipv6_str(ip_int: int) -> str:
        """Конвертира цяло число в IPv6 стринг"""
        parts = []
        for _ in range(8):
            parts.insert(0, format(ip_int & 0xFFFF, '04x'))
            ip_int >>= 16
        return ':'.join(parts)

    def __lt__(self, other) -> bool:
        return self.ip_int < other.ip_int

    def __le__(self, other) -> bool:
        return self.ip_int <= other.ip_int

    def __eq__(self, other) -> bool:
        return self.ip_int == other.ip_int

class Network:
    @staticmethod
    def count_leading_zeros(num: int, bits: int = 32) -> int:
        """
        Имплементация на CLZ (Count Leading Zeros)
        Връща броя на водещите нули в двоичното представяне на число
        """
        if num == 0:
            return bits
        
        count = 0
        mask = 1 << (bits - 1)
        
        while mask > 0 and not (num & mask):
            count += 1
            mask >>= 1
            
        return count

    @staticmethod
    def find_optimal_prefix(start: int, end: int, bits: int = 32) -> int:
        """
        Намира оптималния префикс използвайки CLZ
        """
        if start == end:
            return bits
            
        diff = start ^ end  # XOR за намиране на различаващите се битове
        return bits - (bits - Network.count_leading_zeros(diff, bits))

    def __init__(self, network_str: str):
        """Инициализира мрежа от CIDR нотация"""
        try:
            # Проверка за валиден CIDR формат
            if '/' not in network_str:
                raise ValueError("Моля, въведете IP адрес с префикс (пример: 192.168.1.0/24 или 2001:db8::/32)")
            
            ip_str, prefix_str = network_str.split('/')
            
            # Валидация на префикса
            if not prefix_str.isdigit():
                raise ValueError("Префиксът трябва да бъде число")
            
            self.ip = IP(ip_str)
            self.prefix_length = int(prefix_str)
            
            # Проверка за валиден диапазон на префикса
            max_prefix = 32 if self.ip.version == 4 else 128
            if not (0 <= self.prefix_length <= max_prefix):
                raise ValueError(f"Префиксът трябва да бъде между 0 и {max_prefix}")
            
            # Изчисляване на мрежова маска и адреси
            self._calculate_network_values()
        except ValueError as e:
            raise ValueError(str(e))
        except Exception as e:
            raise ValueError(f"Невалиден CIDR формат. Моля, използвайте формат IP/префикс (пример: 192.168.1.0/24)")

    def _calculate_network_values(self):
        """Изчислява мрежова маска, мрежов и broadcast адреси"""
        bits = 32 if self.ip.version == 4 else 128
        self.netmask_int = ((1 << bits) - 1) ^ ((1 << (bits - self.prefix_length)) - 1)
        self.network_address_int = self.ip.ip_int & self.netmask_int
        self.broadcast_address_int = self.network_address_int | ((1 << (bits - self.prefix_length)) - 1)

    def get_network_address(self) -> str:
        """Връща мрежовия адрес"""
        if self.ip.version == 4:
            return IP._int_to_ipv4_str(self.network_address_int)
        return IP._int_to_ipv6_str(self.network_address_int)

    def get_broadcast_address(self) -> str:
        """Връща broadcast адреса"""
        if self.ip.version == 4:
            return IP._int_to_ipv4_str(self.broadcast_address_int)
        return IP._int_to_ipv6_str(self.broadcast_address_int)

    def get_netmask(self) -> str:
        """Връща мрежовата маска"""
        if self.ip.version == 4:
            return IP._int_to_ipv4_str(self.netmask_int)
        return IP._int_to_ipv6_str(self.netmask_int)

    def get_first_usable(self) -> str:
        """Връща първия използваем IP адрес"""
        if self.ip.version == 4:
            return IP._int_to_ipv4_str(self.network_address_int + 1)
        return IP._int_to_ipv6_str(self.network_address_int + 1)

    def get_last_usable(self) -> str:
        """Връща последния използваем IP адрес"""
        if self.ip.version == 4:
            return IP._int_to_ipv4_str(self.broadcast_address_int - 1)
        return IP._int_to_ipv6_str(self.broadcast_address_int - 1)

    def get_num_addresses(self) -> int:
        """Връща броя на адресите в мрежата"""
        return 1 << (32 if self.ip.version == 4 else 128) - self.prefix_length

def find_optimal_cidrs(start_ip_str: str, end_ip_str: str) -> List[str]:
    """Намира оптималните CIDR блокове между два IP адреса използвайки CLZ"""
    try:
        start_ip = IP(start_ip_str)
        end_ip = IP(end_ip_str)

        if start_ip.version != end_ip.version:
            raise ValueError("IP адресите трябва да са от един и същ тип")

        if start_ip > end_ip:
            start_ip, end_ip = end_ip, start_ip

        result = []
        current_ip = start_ip.ip_int
        end_ip_int = end_ip.ip_int
        bits = 32 if start_ip.version == 4 else 128

        while current_ip <= end_ip_int:
            # Използваме CLZ за намиране на оптималния префикс
            prefix = Network.find_optimal_prefix(current_ip, end_ip_int, bits)
            
            # Намираме маската за текущия префикс
            mask = ((1 << bits) - 1) ^ ((1 << (bits - prefix)) - 1)
            
            # Намираме началото на мрежата
            network_start = current_ip & mask
            
            # Проверяваме дали мрежата започва от текущия IP
            while network_start < current_ip:
                prefix += 1
                if prefix > bits:
                    break
                mask = ((1 << bits) - 1) ^ ((1 << (bits - prefix)) - 1)
                network_start = current_ip & mask

            if start_ip.version == 4:
                result.append(f"{IP._int_to_ipv4_str(current_ip)}/{prefix}")
            else:
                result.append(f"{IP._int_to_ipv6_str(current_ip)}/{prefix}")

            # Преминаваме към следващия блок
            current_ip = (current_ip & ((1 << bits) - (1 << (bits - prefix)))) + (1 << (bits - prefix))

        return result
    except ValueError as e:
        return [f"Грешка: {str(e)}"]

def print_banner():
    """Отпечатва банер на програмата"""
    print("\033[95m")  # Лилав цвят
    print("╔═════════════════════════════════════════════════╗")
    print("║             PURE CIDR КАЛКУЛАТОР               ║")
    print("║        IPv4 и IPv6 - Максимална Скорост        ║")
    print("║               Made by Ivansky                  ║")
    print("╚═════════════════════════════════════════════════╝")
    print("\033[0m")

def analyze_network(cidr: str) -> Dict[str, Union[str, int]]:
    """Анализира CIDR нотация и връща информация за мрежата"""
    try:
        # Базова валидация на входа
        cidr = cidr.strip()
        if not cidr:
            return {"error": "Моля, въведете CIDR нотация"}
        
        # Проверка за правилен формат
        if '/' not in cidr:
            return {"error": "Моля, въведете IP адрес с префикс (пример: 192.168.1.0/24 или 2001:db8::/32)"}
        
        network = Network(cidr)
        info = {
            "IP версия": "IPv6" if network.ip.version == 6 else "IPv4",
            "Мрежов адрес": network.get_network_address(),
            "Broadcast адрес": network.get_broadcast_address(),
            "Мрежова маска": network.get_netmask(),
            "Префикс": network.prefix_length,
            "Брой адреси": network.get_num_addresses(),
            "Първи използваем": network.get_first_usable(),
            "Последен използваем": network.get_last_usable()
        }
        
        if network.ip.version == 4:
            info["Маска (двоично)"] = format(network.netmask_int, '032b')
        else:
            info["Маска (двоично)"] = format(network.netmask_int, '0128b')
            
        return info
    except ValueError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": f"Възникна грешка: {str(e)}"}

def main():
    print_banner()

    while True:
        print("\n\033[94mИзберете опция:\033[0m")
        print("1. Анализ на CIDR нотация (IPv4 или IPv6)")
        print("2. Намиране на оптимални CIDR блокове")
        print("3. Изход")

        choice = input("\nВашият избор (1-3): ").strip()

        if choice == "3":
            print("\n\033[95mДовиждане! Made by Ivansky\033[0m")
            break

        elif choice == "1":
            cidr = input("\nВъведете CIDR нотация (пр. 192.168.1.0/24 или 2001:db8::/32): ").strip()
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