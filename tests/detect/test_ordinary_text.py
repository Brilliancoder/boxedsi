"""Ordinary sentences that hold the look-alikes of the new kinds (passports, social security numbers, VAT, addresses of wallets and
random-looking tokens): none of them is a finding at level 2. They are made up; the differential over the Python library, the
installed packages, this repository and generated prose, logs and configs (see the commit messages) gave no false positive of
PASSPORT, SSN, VAT_ID or CRYPTO_ADDR, and the SECRET rule's are ids, class names and base64 data."""

import pytest

from boxed.detect import detect

SENTENCES = [
    # passports
    "Passport control at Berlin airport took 25 minutes and the passport photo had to be 35x45 mm.",
    "Renew your passport at least 6 months before the trip; the office opens at 9 on weekdays.",
    "My passport expires in 2027, so I will book the flight for May 2026.",
    "Паспорт качества № 12345 приложен к партии, паспорт сделки оформлен по контракту 12/345/6789/0/1.",
    "К заявке приложен технический паспорт здания, инвентарный номер 93378228.",
    "Паспортный стол работает с 9 до 18, заказ № 723785 готов к выдаче.",
    "Серия фильмов выходит по пятницам, номер выпуска 12; серия акций стартует 5 октября.",
    "Заказ 4597 306929 отправлен курьером в Казань.",
    "Получил паспорт. 4510 123456 - номер заказа в магазине.",
    # social security numbers
    "The social security benefits office opens at 8 and the payment reference is 123456.",
    "Part number 123-45-6789 is back in stock; order #234-56-7890 shipped on Monday.",
    "Артикул 123-45-6789 есть на складе, заказ № 234-56-7890 отправлен.",
    "ISBN 978-3-16-148410-0 and the date 2026-10-24 are in the footer; call 800-555-1212 for support.",
    "Reference 1234-56-7890 and 12-345-6789 are no social security numbers.",
    # VAT numbers
    "The price includes VAT at 21%; the IT department, the DE office and the FR office report to the PL team.",
    "Order DK12345678 shipped on 2026-10-24 and SE123456789001 is the parcel code.",
    "Our VAT is high this year, so we raised prices in ES and IT.",
    "Ticket DE-1234567 and the room code PL5260001 are on the list.",
    # wallets
    "Bitcoin trades near 90,000 USD; 1 BTC is about 80 thousand euros in this example.",
    "The class 3DModelingWorkshopDescriptionForTheCustomerPortal is in the 1st module.",
    "Hash 0x1234 and the id 0xdeadbeef are short; a value 0X5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed is not a wallet.",
    # random-looking tokens
    "Commit 3f786850e387550fdab836ed7e6dc881de23001b fixed the build; the image is sha256:" + "ab12" * 16 + ".",
    "Request id 123e4567-e89b-12d3-a456-426614174000 was logged at 10:15.",
    "See https://github.com/anthropics/claude-code/issues/12345?utm_source=newsletter&utm_campaign=Spring2026Launch for details.",
    "The file my-super-long-article-title-for-2026-update-v2-Final.pdf is attached.",
    "Use getUserAccountPermissionsForTenant2 and TestPositionalsNargsNoneZeroOrMore1 as examples.",
    "The path /Users/anna/Projects/Quarterly-Report-2026/final/Budget_v3_FINAL.xlsx is on the share.",
    'integrity="sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC" crossorigin="anonymous"',
    "The alphabet is ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 and the digits are 1234567890.",
    "Meeting notes: Привет, коллеги! Сумма 12 345 678 руб., договор № 713/11 от 17.10.2026, НДС 20%.",
    # the working directory under a name of secrets
    "pwd = /home/user/project",
    "PWD=/home/user/project",
    "export OLD_PWD=~/work/app && cd -",
    # code that reads a secret is no secret
    "password = os.environ['DB_PASSWORD']",
    'password = os.environ["DB_PASSWORD"]',
    "api_key = config.get('api_key')",
    'token = os.getenv("API_TOKEN")',
    "token=get_token()",
    "secret = vault.read(path)",
    "password = sys.argv[1]",
]


@pytest.mark.parametrize("text", SENTENCES)
def test_an_ordinary_sentence_has_no_finding(text):
    assert [(d.kind, d.text) for d in detect(text, level=2)] == []
