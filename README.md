# PURE CIDR Калкулатор

Бърз и ефективен CIDR калкулатор за IPv4 адреси, написан изцяло на Python без външни библиотеки.

## Създаден от Ivansky

## Възможности

- Анализ на CIDR нотация:
  - Мрежов адрес
  - Broadcast адрес
  - Мрежова маска
  - Брой налични адреси
  - Първи и последен използваем адрес
  - Двоичен формат на маската

- Намиране на оптимални CIDR блокове между два IP адреса
  - Автоматично изчисляване на най-ефективните CIDR блокове
  - Пълна информация за всеки блок
  - Бърз алгоритъм с побитови операции

## Примери за използване

### 1. Анализ на CIDR нотация
```bash
Въведете CIDR нотация: 192.168.1.0/24

Резултати:
Мрежов адрес: 192.168.1.0
Broadcast адрес: 192.168.1.255
Мрежова маска: 255.255.255.0
Брой адреси: 256
Първи използваем: 192.168.1.1
Последен използваем: 192.168.1.254
```

### 2. Намиране на оптимални CIDR блокове
```bash
Начален IP: 192.168.1.1
Краен IP: 192.168.2.254

Резултати:
Блок 1: 192.168.1.1/32
Блок 2: 192.168.1.2/31
Блок 3: 192.168.1.4/30
...
```

## Инсталация

```bash
git clone https://github.com/GhostNeraCode/cidrs-calculator.git
cd cidrs-calculator
python pure_cidr_calculator.py
```

## Технически детайли

- Написан на чист Python без външни зависимости
- Използва ефективни побитови операции
- Поддържа IPv4 адреси
- Цветен интерфейс за по-добра четимост

## Лиценз

MIT License 