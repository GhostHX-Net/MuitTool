import random
from typing import List, Optional
NUMBERS = list("123456789")
LETTERS_UP = list("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
LETTERS_LOW = list("abcdefghijklmnopqrstuvwxyz")
SYMBOLS = list("!@#$%^&*()-_=+[]|")
def generate_password(
    include_numbers: bool = True,
    include_letters: bool = True,
    include_symbols: bool = True,
    length: int = 16
) -> str:
    if length < 4:
        length = 16  
    pool: List[str] = []
    if include_numbers:
        pool.extend(random.sample(NUMBERS, k=min(4, len(NUMBERS))))
    if include_letters:
        pool.extend(random.sample(LETTERS_UP, k=min(4, len(LETTERS_UP))))
        pool.extend(random.sample(LETTERS_LOW, k=min(4, len(LETTERS_LOW))))
    if include_symbols:
        pool.extend(random.sample(SYMBOLS, k=min(4, len(SYMBOLS))))
    remaining = length - len(pool)
    if remaining > 0:
        all_available = (
            (NUMBERS if include_numbers else []) +
            (LETTERS_UP + LETTERS_LOW if include_letters else []) +
            (SYMBOLS if include_symbols else [])
        )
        if not all_available:
            raise ValueError("No character types selected")
        pool.extend(random.choices(all_available, k=remaining))
    random.shuffle(pool)
    return "".join(pool)
def generate_custom_password(choices: str, custom_length: Optional[int] = None) -> Optional[str]:
    length = custom_length or 16
    parts = [p.strip() for p in choices.replace(" ", "").split(",") if p.strip()]
    include_nums = "1" in parts
    include_lets = "2" in parts
    include_syms = "3" in parts
    if not (include_nums or include_lets or include_syms):
        print("Invalid choice: Please select at least one option (1, 2, or 3)")
        return None
    return generate_password(
        include_numbers=include_nums,
        include_letters=include_lets,
        include_symbols=include_syms,
        length=length
    )
def main() -> None:
    print("Password Generator")
    print("1: [+] Numbers")
    print("2: [+] Letters (Mixed Case)")
    print("3: [+] Symbols")
    print("1,2,3: [+] All Components\n")
    user_input = input("Enter your choice (e.g. 1 or 1,2 or 1, 3): ")  
    try:
        length_input = input("Enter password length (default 16): ").strip()
        length = int(length_input) if length_input else 16
    except ValueError:
        length = 16
    password = generate_custom_password(user_input, length)
    if password:
        print(f"\nGenerated Password: {password}")
def Pwd():
    pwd1 = generate_password(length=5, include_symbols=True)
    pwd2 = generate_password(length=5, include_letters=True)
    pwd3 = generate_password(length=5, include_numbers=True)
    pwd4 = pwd1 + pwd2 + pwd3
    print(pwd4)
Pwd()


