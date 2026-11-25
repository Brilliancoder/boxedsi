"""Seeded generator of synthetic EN, RU and mixed documents: logs, configs, code, transcripts, keys, tables, contracts, emails.

Nothing here is a real person or a real company's data: names are common ones combined at random, companies are made-up
words, e-mail domains are the reserved example.com, example.org and example.net, IPs are documentation ranges, UK numbers
are Ofcom's drama range and Russian numbers use the area code 000, which does not exist. Keys and cards are random.
"""

import random
import string
from collections import Counter
from dataclasses import dataclass, field

FIRST = ["anna", "ivan", "maria", "john", "olga", "peter", "li", "sara"]
LAST = ["petrov", "smith", "ivanova", "lee", "garcia", "novak"]
DOMAINS = ["example.com", "example.org", "example.net"]
UPPER_DIGITS = string.ascii_uppercase + string.digits
ALNUM = string.ascii_letters + string.digits
B64URL = ALNUM + "-_"
B64 = ALNUM + "+/"

FIRST_EN = ["Anna", "Daniel", "Emily", "Henry", "John", "Lucas", "Maria", "Nina", "Oliver", "Peter", "Sara", "Sophie"]
LAST_EN = ["Brown", "Dubois", "Fischer", "Garcia", "Keller", "Novak", "Rossi", "Smith", "Walker", "Weber"]
# Russian given names by sex (True = female): nominative, genitive, Latin spelling for e-mail addresses
FIRST_RU = {
    False: [
        ("Иван", "Ивана", "ivan"),
        ("Пётр", "Петра", "petr"),
        ("Алексей", "Алексея", "alexey"),
        ("Дмитрий", "Дмитрия", "dmitry"),
        ("Сергей", "Сергея", "sergey"),
        ("Андрей", "Андрея", "andrey"),
    ],
    True: [
        ("Анна", "Анны", "anna"),
        ("Мария", "Марии", "maria"),
        ("Ольга", "Ольги", "olga"),
        ("Елена", "Елены", "elena"),
        ("Наталья", "Натальи", "natalia"),
        ("Ирина", "Ирины", "irina"),
    ],
}
# Russian surnames: masculine (its genitive is the feminine form), feminine genitive, Latin spelling
LAST_RU = [
    ("Петров", "Петрова", "Петровой", "petrov"),
    ("Иванов", "Иванова", "Ивановой", "ivanov"),
    ("Смирнов", "Смирнова", "Смирновой", "smirnov"),
    ("Кузнецов", "Кузнецова", "Кузнецовой", "kuznetsov"),
    ("Соколов", "Соколова", "Соколовой", "sokolov"),
    ("Морозов", "Морозова", "Морозовой", "morozov"),
    ("Волков", "Волкова", "Волковой", "volkov"),
    ("Новиков", "Новикова", "Новиковой", "novikov"),
]
ORG_STEMS = {
    "en": ["Valtrix", "Norlen", "Kestrel", "Brightwell", "Halden", "Lumera", "Fjordline", "Stonebridge"],
    "ru": ["Вельтор", "Нордекс", "Лумера", "Гранитекс", "Брайтвел", "Тандем", "Кестрел", "Фьордлайн"],
}
ORG_KINDS = {
    "en": ["Systems", "Logistics", "Partners", "Holdings", "Trading", "Consulting"],
    "ru": ["Системы", "Логистика", "Партнёры", "Холдинг", "Трейдинг", "Консалтинг"],
}
LEGAL_FORMS = {"en": ["Ltd", "LLC", "Inc", "GmbH"], "ru": ["ООО", "АО"]}
MONTHS = {"en": ["October", "November", "December"], "ru": ["октября", "ноября", "декабря"]}
SERVICES = ["billing", "crm", "reports", "mailer", "storage"]


@dataclass
class BenchDoc:
    id: str
    lang: str  # en, ru or mixed
    text: str
    labels: list[tuple[int, int, str]] = field(default_factory=list)
    genre: str = ""  # log_en, table_ru, mixed, ...


@dataclass(frozen=True)
class Person:
    first: str
    full: str
    gen: str  # the full name in the genitive ("в лице Ивана Петрова"); the same as full in English
    email: str
    female: bool = False  # Russian only: verbs and participles about the person agree with it


@dataclass(frozen=True)
class Org:
    lang: str
    name: str  # what the label covers: the legal form stays outside it
    legal: str


class _Builder:
    def __init__(self) -> None:
        self.parts: list[str] = []
        self.labels: list[tuple[int, int, str]] = []
        self.pos = 0

    def text(self, s: str) -> "_Builder":
        self.parts.append(s)
        self.pos += len(s)
        return self

    def value(self, s: str, kind: str) -> "_Builder":
        self.labels.append((self.pos, self.pos + len(s), kind))
        return self.text(s)

    def person(self, p: Person, form: str = "full") -> "_Builder":
        return self.value({"full": p.full, "first": p.first, "gen": p.gen}[form], "PERSON")

    def org(self, o: Org) -> "_Builder":
        if o.lang == "ru":
            return self.text(f'{o.legal} "').value(o.name, "ORG").text('"')
        return self.value(o.name, "ORG").text(f" {o.legal}")


def _chars(rng: random.Random, alphabet: str, n: int) -> str:
    return "".join(rng.choice(alphabet) for _ in range(n))


def _email(rng):
    return f"{rng.choice(FIRST)}.{rng.choice(LAST)}{rng.randint(1, 99)}@{rng.choice(DOMAINS)}"


def _phone(rng, lang=None):
    """Numbers that cannot belong to anyone: the Russian area code 000 does not exist, 020 7946 0xxx is Ofcom's drama range."""
    if lang == "ru" or (lang is None and rng.random() < 0.5):
        return f"{rng.choice(['+7', '8'])} (000) {rng.randint(100, 999)}-{rng.randint(10, 99)}-{rng.randint(10, 99)}"
    return f"+44 20 7946 0{rng.randint(0, 999):03d}"


def _ip(rng):
    return f"{rng.choice(['203.0.113', '198.51.100'])}.{rng.randint(1, 254)}"


def _luhn_complete(prefix: str) -> str:
    total = 0
    for i, ch in enumerate(reversed(prefix)):
        n = int(ch)
        if i % 2 == 0:
            n = n * 2 - 9 if n * 2 > 9 else n * 2
        total += n
    return prefix + str((10 - total % 10) % 10)


def _card(rng, spaced=True):
    digits = _luhn_complete("4" + _chars(rng, string.digits, 14))
    return " ".join(digits[i : i + 4] for i in range(0, 16, 4)) if spaced else digits


def _iban(rng):
    bban = _chars(rng, string.digits, 18)
    check = 98 - int(bban + "131400") % 97
    compact = f"DE{check:02d}{bban}"
    return " ".join(compact[i : i + 4] for i in range(0, len(compact), 4))


def _jwt(rng):
    return f"eyJ{_chars(rng, B64URL, 20)}.eyJ{_chars(rng, B64URL, 30)}.{_chars(rng, B64URL, 40)}"


def _private_key(rng):
    body = "\n".join(_chars(rng, B64, 64) for _ in range(3))
    return f"-----BEGIN RSA PRIVATE KEY-----\n{body}\n-----END RSA PRIVATE KEY-----"


def _api_key(rng):
    return rng.choice(
        [
            lambda: "AKIA" + _chars(rng, UPPER_DIGITS, 16),
            lambda: "ghp_" + _chars(rng, ALNUM, 36),
            lambda: "sk-" + _chars(rng, ALNUM, 40),
            lambda: "sk_live_" + _chars(rng, ALNUM, 24),
        ]
    )()


def _password(rng):
    return _chars(rng, ALNUM, 12)


def _ts(rng):
    return f"2026-10-0{rng.randint(1, 9)} 10:{rng.randint(10, 59)}:00"


def _date(rng, lang):
    suffix = " г." if lang == "ru" else ""
    return f"{rng.randint(1, 28)} {rng.choice(MONTHS[lang])} 2026{suffix}"


def _money(rng, lang):
    amount = rng.randint(10, 990) * 50
    return f"EUR {amount:,}.00" if lang == "en" else f"{amount:,}".replace(",", " ") + ",00 EUR"


def _clause_ref(rng):
    return ".".join(str(rng.randint(1, 9)) for _ in range(4))


def _person(rng, lang):
    female = False
    if lang == "en":
        first, last = rng.choice(FIRST_EN), rng.choice(LAST_EN)
        full = gen = f"{first} {last}"
        latin = f"{first}.{last}".lower()
    else:
        female = rng.random() < 0.5
        first, first_gen, first_latin = rng.choice(FIRST_RU[female])
        masculine, feminine, feminine_gen, last_latin = rng.choice(LAST_RU)
        last, last_gen = (feminine, feminine_gen) if female else (masculine, feminine)
        full, gen, latin = f"{first} {last}", f"{first_gen} {last_gen}", f"{first_latin}.{last_latin}"
    return Person(first, full, gen, f"{latin}{rng.randint(1, 99)}@{rng.choice(DOMAINS)}", female)


def _org(rng, lang):
    return Org(lang, f"{rng.choice(ORG_STEMS[lang])} {rng.choice(ORG_KINDS[lang])}", rng.choice(LEGAL_FORMS[lang]))


def log_en(b, rng):
    b.text(f"{_ts(rng)} INFO login user=").value(_email(rng), "EMAIL").text(" ip=").value(_ip(rng), "IP")
    b.text(f"\n{_ts(rng)} WARN payment card=").value(_card(rng), "CARD").text(" declined\n")


def log_ru(b, rng):
    b.text(f"{_ts(rng)} вход пользователя ").value(_email(rng), "EMAIL").text(" с адреса ").value(_ip(rng), "IP")
    b.text("\nоплата картой ").value(_card(rng), "CARD").text(" отклонена\n")


def config(b, rng, comment):
    b.text(f"# {comment}\nDB_PASSWORD=").value(_chars(rng, ALNUM, 12), "SECRET")
    b.text("\nAWS_ACCESS_KEY_ID=").value("AKIA" + _chars(rng, UPPER_DIGITS, 16), "SECRET")
    b.text("\nGITHUB_TOKEN=").value("ghp_" + _chars(rng, ALNUM, 36), "SECRET")
    b.text("\nADMIN_EMAIL=").value(_email(rng), "EMAIL").text("\n")


def code_en(b, rng):
    b.text('def notify():\n    send("').value(_email(rng), "EMAIL").text('", auth="Bearer ').value(_jwt(rng), "JWT").text('")\n')


def code_ru(b, rng):
    b.text('# отправка уведомления\nsend("').value(_email(rng), "EMAIL").text('", token="').value(_jwt(rng), "JWT").text('")\n')


def transcript_en(b, rng):
    b.text("Speaker 1: call me at ").value(_phone(rng), "PHONE").text(" or write to ").value(_email(rng), "EMAIL")
    b.text(".\nSpeaker 2: my IBAN is ").value(_iban(rng), "IBAN").text(", thanks.\n")


def transcript_ru(b, rng):
    b.text("Спикер 1: позвоните мне ").value(_phone(rng), "PHONE").text(" или напишите на ").value(_email(rng), "EMAIL")
    b.text(".\nСпикер 2: реквизиты, IBAN ").value(_iban(rng), "IBAN").text(", спасибо.\n")


def key(b, rng, intro):
    b.text(f"{intro}:\n").value(_private_key(rng), "PRIVATE_KEY").text("\n")


# CSV columns as (English header, Russian header, kind of cell); a table picks one of these
TABLES = [
    [
        ("id", "№", "id"),
        ("contact", "Контакт", "person"),
        ("company", "Компания", "org"),
        ("email", "Email", "email"),
        ("phone", "Телефон", "phone"),
    ],
    [
        ("order", "Заказ", "order"),
        ("payer", "Плательщик", "person"),
        ("card", "Карта", "card"),
        ("iban", "IBAN", "iban"),
        ("amount", "Сумма", "amount"),
        ("date", "Дата", "date"),
    ],
    [("service", "Сервис", "service"), ("owner", "Владелец", "email"), ("api_key", "Ключ API", "key"), ("created", "Создан", "date")],
]


def _cell(b, rng, lang, kind, row, person, org):
    if kind == "id":
        b.text(str(row))
    elif kind == "person":
        b.person(person)
    elif kind == "org":
        b.value(org.name, "ORG")
    elif kind == "email":
        b.value(person.email, "EMAIL")
    elif kind == "phone":
        b.value(_phone(rng, lang), "PHONE")
    elif kind == "card":
        b.value(_card(rng, spaced=rng.random() < 0.5), "CARD")
    elif kind == "iban":
        b.value(_iban(rng), "IBAN")
    elif kind == "key":
        b.value(_api_key(rng), "SECRET")
    elif kind == "order":
        b.text(f"ORD-202610{rng.randint(1, 28):02d}-{rng.randint(1, 99)}")
    elif kind == "amount":
        amount = f"{rng.randint(100, 9999)}.{rng.randint(0, 99):02d}"
        b.text(amount if lang == "en" else amount.replace(".", ","))
    elif kind == "date":
        day = f"2026-10-{rng.randint(1, 28):02d}"
        b.text(day if lang == "en" else ".".join(reversed(day.split("-"))))
    else:
        b.text(rng.choice(SERVICES))


def table(b, rng, lang):
    columns = rng.choice(TABLES)
    sep = "," if lang == "en" else ";"
    b.text(sep.join(en if lang == "en" else ru for en, ru, _ in columns) + "\n")
    for row in range(1, rng.randint(3, 6) + 1):
        person, org = _person(rng, lang), _org(rng, lang)
        for i, (_, _, kind) in enumerate(columns):
            if i:
                b.text(sep)
            _cell(b, rng, lang, kind, row, person, org)
        b.text("\n")


def contract_en(b, rng):
    supplier, customer = _org(rng, "en"), _org(rng, "en")
    director, buyer = _person(rng, "en"), _person(rng, "en")
    b.text(f"SERVICES AGREEMENT No. {rng.randint(10, 99)}/2026\n\nThis Agreement is made on {_date(rng, 'en')} between ")
    b.org(supplier).text(' ("Supplier"), represented by its director ').person(director).text(", and ")
    b.org(customer).text(' ("Customer"), represented by ').person(buyer).text(".\n\n")
    b.text("1. Subject\n1.1. The Supplier provides the consulting services listed in Annex 1.\n")
    if rng.random() < 0.5:
        b.text(f"1.2. Acceptance follows clause {_clause_ref(rng)} of Annex 1.\n")
    b.text(f"\n2. Price and payment\n2.1. The price is {_money(rng, 'en')}. The Customer pays within 10 days to IBAN ")
    b.value(_iban(rng), "IBAN").text(".\n2.2. Late payment bears a penalty of 0.1% per day.\n\n")
    b.text("3. Notices\n3.1. To the Supplier: ").person(director).text(", ").value(director.email, "EMAIL").text(", tel. ")
    b.value(_phone(rng, "en"), "PHONE").text(".\n3.2. To the Customer: ").person(buyer).text(", ").value(buyer.email, "EMAIL")
    b.text(", tel. ").value(_phone(rng, "en"), "PHONE").text(".\n\n")
    b.text("4. Final provisions\n4.1. This Agreement is governed by the law of England and Wales.\n\nSignatures\n")
    b.org(supplier).text(": ").person(director).text(", Director\n").org(customer).text(": ").person(buyer).text("\n")


def contract_ru(b, rng):
    supplier, customer = _org(rng, "ru"), _org(rng, "ru")
    director, buyer = _person(rng, "ru"), _person(rng, "ru")
    b.text(f"ДОГОВОР ОКАЗАНИЯ УСЛУГ № {rng.randint(10, 99)}/2026\n\nг. Москва, {_date(rng, 'ru')}\n\n")
    acting = "действующей" if director.female else "действующего"
    b.org(supplier).text(', именуемое в дальнейшем "Исполнитель", в лице директора ').person(director, "gen")
    b.text(f", {acting} на основании Устава, и ").org(customer).text(', именуемое в дальнейшем "Заказчик", в лице ')
    b.person(buyer, "gen").text(", заключили настоящий договор о нижеследующем.\n\n")
    b.text("1. Предмет договора\n1.1. Исполнитель оказывает консультационные услуги, перечисленные в Приложении 1.\n")
    if rng.random() < 0.5:
        b.text(f"1.2. Приёмка проводится по п. {_clause_ref(rng)} Приложения 1.\n")
    b.text(f"\n2. Стоимость и порядок расчётов\n2.1. Стоимость услуг составляет {_money(rng, 'ru')}. ")
    b.text("Заказчик оплачивает в течение 10 дней на счёт IBAN ")
    b.value(_iban(rng), "IBAN").text(".\n2.2. За просрочку платежа начисляется пеня 0,1% за каждый день.\n\n")
    b.text("3. Уведомления\n3.1. Исполнителю: ").person(director).text(", ").value(director.email, "EMAIL").text(", тел. ")
    b.value(_phone(rng, "ru"), "PHONE").text(".\n3.2. Заказчику: ").person(buyer).text(", ").value(buyer.email, "EMAIL")
    b.text(", тел. ").value(_phone(rng, "ru"), "PHONE").text(".\n\n")
    b.text("4. Заключительные положения\n4.1. Договор регулируется правом Российской Федерации.\n\nПодписи сторон\n")
    b.org(supplier).text(": ").person(director).text(", директор\n").org(customer).text(": ").person(buyer).text("\n")


def email_en(b, rng):
    sender, receiver, org = _person(rng, "en"), _person(rng, "en"), _org(rng, "en")
    b.text("From: ").person(sender).text(" <").value(sender.email, "EMAIL").text(">\nTo: ")
    b.person(receiver).text(" <").value(receiver.email, "EMAIL").text(">\n")
    if rng.random() < 0.5:
        b.text("Cc: ").value(f"accounts@{rng.choice(DOMAINS)}", "EMAIL")
        b.text(f"\nSubject: Invoice {rng.randint(100, 999)} for October\nDate: {_date(rng, 'en')}, 10:{rng.randint(10, 59)}\n\nHi ")
        b.person(receiver, "first").text(f",\n\nPlease find the invoice attached: {_money(rng, 'en')}, due on {_date(rng, 'en')}.\n")
        b.text("Payment details: IBAN ").value(_iban(rng), "IBAN").text(". You can also pay by card, call me on ")
        b.value(_phone(rng, "en"), "PHONE").text(".\n")
    else:
        b.text(f"Subject: Access to the reporting portal\nDate: {_date(rng, 'en')}, 10:{rng.randint(10, 59)}\n\nHello ")
        b.person(receiver, "first").text(",\n\nYour account for the reporting portal is ready.\n\nLogin: ")
        b.value(receiver.email, "EMAIL").text("\nPassword: ").value(_password(rng), "SECRET")
        b.text("\n\nPlease change the password after the first login. Support contact: ")
        b.person(sender, "first").text(", ").value(_phone(rng, "en"), "PHONE").text(".\n")
    b.text("\nBest regards,\n").person(sender).text("\nAccount manager, ").org(org)
    b.text("\ntel. ").value(_phone(rng, "en"), "PHONE").text("\n")


def email_ru(b, rng):
    sender, receiver, org = _person(rng, "ru"), _person(rng, "ru"), _org(rng, "ru")
    b.text("От: ").person(sender).text(" <").value(sender.email, "EMAIL").text(">\nКому: ")
    b.person(receiver).text(" <").value(receiver.email, "EMAIL").text(">\n")
    if rng.random() < 0.5:
        b.text("Копия: ").value(f"accounts@{rng.choice(DOMAINS)}", "EMAIL")
        b.text(f"\nТема: Счёт № {rng.randint(100, 999)} за октябрь\nДата: {_date(rng, 'ru')}, 10:{rng.randint(10, 59)}\n\n")
        b.text("Добрый день, ").person(receiver, "first")
        b.text(f"!\n\nВо вложении счёт на сумму {_money(rng, 'ru')}, срок оплаты - до {_date(rng, 'ru')}\n")
        b.text("Реквизиты для оплаты: IBAN ").value(_iban(rng), "IBAN").text(". Оплатить можно и картой, звоните: ")
        b.value(_phone(rng, "ru"), "PHONE").text(".\n")
    else:
        b.text(f"Тема: Доступ к порталу отчётности\nДата: {_date(rng, 'ru')}, 10:{rng.randint(10, 59)}\n\nЗдравствуйте, ")
        b.person(receiver, "first").text("!\n\nВаша учётная запись в портале отчётности готова.\n\nЛогин: ")
        b.value(receiver.email, "EMAIL").text("\nПароль: ").value(_password(rng), "SECRET")
        b.text("\n\nСмените пароль после первого входа. Контакт поддержки: ")
        b.person(sender, "first").text(", ").value(_phone(rng, "ru"), "PHONE").text(".\n")
    b.text("\nС уважением,\n").person(sender).text("\nМенеджер по работе с клиентами, ").org(org).text("\nтел. ")
    b.value(_phone(rng, "ru"), "PHONE").text("\n")


def _russian_sentence(b, rng):
    """A Russian sentence with Latin names, as in a team that works with foreign partners."""
    org, person = _org(rng, "en"), _person(rng, "en")
    choice = rng.randint(0, 2)
    if choice == 0:
        b.text("Коллеги из ").org(org).text(" (").person(person).text(", ").value(person.email, "EMAIL")
        b.text(") просят прислать акт до пятницы.\n")
    elif choice == 1:
        b.text("Реквизиты для оплаты: получатель ").org(org).text(", IBAN ").value(_iban(rng), "IBAN").text(". Вопросы - ")
        b.person(person).text(", ").value(_phone(rng, "en"), "PHONE").text(".\n")
    else:
        b.text("Для теста используйте заголовок Authorization: Bearer ").value(_jwt(rng), "JWT")
        b.text(", тестовый пользователь - ").person(person).text(" (").value(person.email, "EMAIL").text(").\n")


def _english_sentence(b, rng):
    """An English sentence with Russian names, as in a mail to a Russian partner."""
    org, person = _org(rng, "ru"), _person(rng, "ru")
    if rng.random() < 0.5:
        b.text("Please forward the invoice to ").person(person).text(" at ").org(org)
        b.text(", tel. ").value(_phone(rng, "ru"), "PHONE").text(".\n")
    else:
        b.text("The agreement was signed by ").person(person).text(" (").org(org)
        b.text("); send a copy to ").value(person.email, "EMAIL").text(".\n")


def mixed(b, rng):
    order = [_russian_sentence, _english_sentence] * 2
    if rng.random() < 0.5:
        order.reverse()
    for sentence in order:
        sentence(b, rng)


TEMPLATES = {
    "en": [
        ("log_en", log_en),
        ("config_en", lambda b, r: config(b, r, "database access")),
        ("code_en", code_en),
        ("transcript_en", transcript_en),
        ("key_en", lambda b, r: key(b, r, "deploy key")),
        ("table_en", lambda b, r: table(b, r, "en")),
        ("contract_en", contract_en),
        ("email_en", email_en),
    ],
    "ru": [
        ("log_ru", log_ru),
        ("config_ru", lambda b, r: config(b, r, "доступ к базе")),
        ("code_ru", code_ru),
        ("transcript_ru", transcript_ru),
        ("key_ru", lambda b, r: key(b, r, "ключ для деплоя")),
        ("table_ru", lambda b, r: table(b, r, "ru")),
        ("contract_ru", contract_ru),
        ("email_ru", email_ru),
    ],
    "mixed": [("mixed", mixed)],
}
LANG_CYCLE = ("en", "ru", "en", "ru", "mixed")  # two fifths English, two fifths Russian, a fifth with both languages in one text


def generate(seed: int, n_docs: int) -> list[BenchDoc]:
    rng = random.Random(seed)
    seen: Counter[str] = Counter()
    docs = []
    for i in range(n_docs):
        lang = LANG_CYCLE[i % len(LANG_CYCLE)]
        genre, template = TEMPLATES[lang][seen[lang] % len(TEMPLATES[lang])]  # genres in turn, so every one is always present
        seen[lang] += 1
        b = _Builder()
        template(b, rng)
        docs.append(BenchDoc(id=f"doc-{i:04d}", lang=lang, text="".join(b.parts), labels=b.labels, genre=genre))
    return docs
