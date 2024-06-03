Simona Češková xcesko00  
KRY Projekt 2: MAC za použití SHA-256 & Length extension attack  
30.04.2024


# Popis řešení
Tyto hlavní body jsou vypracované v funkcích, které jsou volané z funkce ``argument_parser()`` podle zadaných argumentů:
1) SHA-256 ``SHA()``
2) generování MAC pro vstupní zprávu a tajný klíč ``SHA()``, kde se přidá klíč na začátku stringu zprávy
3) ověření MAC pro vstupní zprávu a tajný klíč ``MAC()``
4) length extension attack ``length_extension()``

Začátek projektu je funkce ``argument_parser()``, který rozparsuje argumenty pro volání správných funkcí. Zároveň zkontroluje jestli jsou parametry volány ve správném formátu. Pro kontrolu klíče ``-k KEY`` a ``-a MSG`` jsou funkce: ``regex_KEY_check()`` a ``regex_SMG_check()``.

## SHA-256
Pro výpočet SHA byly vytvořeny pomocné funkce na začátku projektu. ``SHA()`` nejdříve rozdělí původní celou zprávu na menší části M, které postupně aplikuje na zbývající kroky. Funkce ``message_schedule()`` vypočítá rovnice pro message schedule a vrátí bloky W_0-64. ``calculate_constants()`` vypočítá proměnných a-h. ``give_H_i()`` vrátí inicializační konstanty pro H_0 až H_7. Jako poslední krok přepočítání konstant se vykoná přímo v ``SHA()``. Pro poslední část zprávy je použit ``parse_message_block()``, který zformátuje zprávu spolu s její délkou.

## MAC
Spočítá se SHA pomocí ``SHA()`` s rozdílem, že ke zprávě se přidá klíč zavolané z ``MAC()``. Následně porovná, zda je vstupní MAC je stejný jako spočítaný.

## Extension attack
Funkce ``length_extension()`` volá:
1) ``extension()`` Výpočítá padding původní zprávy s přiloženým ``-n`` parametrem pro doplnění délky. Poté naformátuje tento string pomocí ``parse_message_block()``. Tento string (``binary_message_string_block``) se použije pro výpočet nové délky. Jeho délka + délka ``MSG`` z parametru ``-a`` se znovu vloží do funkce ``parse_message_block()``. Výsledek této funkce je naformátovaný string ``extension_string`` - lenght extension attack pomocí ``MSG`` pro výpočet SHA-256.
2) ``give_H_i_MAC()`` - Inicializace konstant H_0 až H_7 v tomto případě probíhá přes rozdělení vstupní MAC zprávy z parametru ``-m`` na 8 částí. Každá tato část je přiřezena jedné H konstantě.
3) ``extension_SHA()`` - Vypočítá se SHA-256 pro length extension attack jako string ``extension_string``.
3) ``SHA_print()`` - Výpis hotové SHA-256 extension length attacku.
4) ``extension_padding()`` - Vytvoření paddingu pro výpis. Vezme původní zprávu, klasicky ji parsuje do formátu pro SHA % 512 = 0. Pro H_0-H_7 použije funkci ``give_H_i()``, přidá bit ``1``, převede původní zprávu do binární podoby. Pomocí ``parse_message_block()`` (délka = zpráva + parametr ``-n``) se naformátuje správně a zavolá funkce ``print_extension_message()``. Tato funkce postupně bere jednolitvé bity zprávy a tiskne je na výstup v daném formátu a pořadí. Na konec se výstup vytiskne ``MSG`` z vstupního parametru ``-a``.

# Kompilace
Pro kompilaci použít ``make``. Příklady vstupů spouštění programu:

```
echo -ne "zprava" | ./kry -c

echo -ne "zprava" | ./kry -s -k heslo

echo -ne "zprava" | ./kry -v -k heslo -m 23158796a45a9392951d9a72dffd6a539b14a07832390b937b94a80ddb6dc18e

echo -ne "message" | ./kry -v -k password -m 23158796a45a9392951d9a72dffd6a539b14a07832390b937b94a80ddb6dc18e

echo -ne "zprava" | ./kry -e -n 5 -a ==message -m 23158796a45a9392951d9a72dffd6a539b14a07832390b937b94a80ddb6dc18e

```

# Parametry
``-c`` Vypočte a tiskne SHA-256 checksum.  
``-s`` Vypočte MAC, použitím implementované SHA-256. Kombinace s: ``-k KEY``  
``-v`` Ověří MAC pro daný klíč a vstupní zprávu. Kombinace s: ``-k KEY, -m CHS``  
``-e`` Provede length extension útok na MAC a vstupní zprávu. Kombinace s: ``-n NUM, -m CHS, -a MSG``  
##

``-k KEY`` – Specifikuje tajný klíč pro výpočet MAC.  
``-m CHS`` – Specifikuje MAC vstupní zprávy pro jeho verifikace či provedení
útoku.  
``-n NUM`` – Specifikuje délku tajného klíče.  
``-a MSG`` – Specifikuje prodloužení vstupní zprávy pro provedení
útoku.  
