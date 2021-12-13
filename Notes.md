# Flare-On v8 — 2021
## Challenge 1 — credchecker
- HTML page with business logic in `<script>` tag
- Flag is XOR decoded with credentials:
	- username: `Admin`
	- password: `Z29sZGVudGlja2V0` (`goldenticket` base-64 encoded)

Flag: `enter_the_funhouse@flare-on.com`

## Challenge 2 — known
- KD4wXzApPiBJdCdzIGRhbmdlcm91cyB0byBhZGQrcm9yIGFsb25lISBUYWtlIHRoaXMgPCgwXzA8KQo=
	- *(>0_0)> It's dangerous to add+ror alone! Take this <(0_0<)*

- decryption key: **8 bytes long**
- error for `Files` directory not present:
	- `SetCurrentDirectory("Files") failed: error code 2`

Flag: `You_Have_Awakened_Me_Too_Soon_EXE@flare-on.com`

## Challenge 3 — antioch
- Docker images?
- extract `layer.tar` to `.dat` files, except `70` directory -> AntiochOS ELF file
- 31 directories
- used `strace` to figure out system calls (`open, read, write, close`)
- see script for cracking CRC32 hashes
- follow order and append all files via bash
- Flag: `Five-Is-Right-Out@flare-on.com`

## Challenge 4 — MyAquaticLife
- executable packed with standard UPX (5 MB)
- unpack with `upx -d ...`
- set up ? and locate DLL embedded in binary (`fathom.dll`) is dropped to user folder
- referenced string: `you chose poorly..`
- `PluginFunc19` export triggered when clicking on the program's central text
- 16 images: when any is clicked, `SetFile` is called
- user input (based on clicks) manipulated, hashed, and checked against the MD5 hash `6c5215b12a10e936f8de1e42083ba184`

Hex constants XOR'ed and substracted for decrypting input to be hashed
- `169E81F938E5AF9F909A96A3A9A42596`
- `00A8A3FCD1A79DD2BA8F8F87A4E4CBF9`

### DLL Functions (ordered by call)
Export | Address | Note
-------| --------| ----
GetType | `73382E00` | XOR esi,esi
GetInfo | `73382DD0` | Sets a string
Copyright | `73382D80` | Sets a string
SetParentWindow | `73383350` | Stores arg0 in memory
SetString | `733833E0` | ?
SetPath | `73383360` | Sets the path where the binary is run
Draw | `73382D90` | Graphics stuff
==SetFile== | `73383050` | Called on image click
==PluginFunc19== | `73382E40` | Main func; MD5 comparison
GetFile | `73382DB0` | Does something with `const1`

### Animals
Position | Value | Part
-------- | ----- | ----
`[0][0]` | `derelict:MZZWP` | 1
`[0][1]` | `lagan:BAJkR` | 2
`[0][2]` | `flotsam:DFWEyEW` | 2
`[0][3]` | `flotsam:PXopvM` | 1
`[1][0]` | `derelict:LDNCVYU` | 2
`[1][1]` | `derelict:yXQsGB` | 3
`[1][2]` | `jetsam:newaui` | 2
`[1][3]` | `lagan:QICMX` | 3
`[2][0]` | `lagan:rOPFG` | 1
`[2][1]` | `jetsam:HwdwAZ` | 1
`[2][2]` | `jetsam:SLdkv` | 1
`[2][3]` | `derelict:LSZvYSFHW` | 2
`[3][0]` | `flotsam:BGgsuhn` | 3
`[3][1]` | `derelict:LSZvYSFHW` | 2
`[3][2]` | `derelict:RTYXAc` | 4
`[3][3]` | `lagan:GTXI` | 2

### Analysis
- `derelict` and `lagan` keys only set but **not checked**
- at `73382E6B`
	- load `flotsam` key to `ESI` (`DFWEyEW` || `PXopvM` || `BGgsuhn`)
	- load `jetsam` key to `EAX` (`newaui` || `HwdwAZ` || `SLdkv`)
- max lengths (to be tested):
	- `flotsam` == 20; e.g., `DFWEyEWDFWEyEWPXopvM`, `PXopvMPXopvMPXopvM` (?)
	- `jetsam` == 17; e.g., `newauiHwdwAZSLdkv` 
	- sum <= 31 (+ null byte == 32 bytes)
- key based on a set of 6 animals (could be repeated, i.e. clicked more than once)
- `newauiHwdwAZSLdkv`
- `sub cl, [eax+edx]  # cl=seed_byte,[eax+edx]=jetsam_byte`
- Python script to brute force combinations and hash 👇

```python
import binascii
from hashlib import md5


combs, flotsam_combs, jetsam_combs = [], [], []


def generate_combinations(array, values):
    for i in range(3):
        for j in range(3):
            for k in range(3):
                comb = values[i] + values[j] + values[k]
                if len(comb) <= 20:
                    array.append(comb)

    for i in range(3):
        for j in range(3):
            comb = values[i] + values[j]
            if len(comb) <= 20:
                array.append(comb)
    
    for i in range(3):
        comb = values[i]
        array.append(comb)


def generate_meta_combinations(length):
    for i in range(length):
        for j in range(length):
            try:
                combs.append([flotsam_combs[i], jetsam_combs[j]])
            except IndexError:
                continue

    print(f'[*] Generated {len(combs)} combinations')


def crack():
    seed = binascii.unhexlify(
        '9625A4A9A3969A909FAFE538F9819E16F9CBE4A4878F8FBAD29DA7D1FCA3A800'
    )

    for comb in combs:
        decrypted_input = ''
        flotsam, jetsam = comb[0], comb[1]

        # Generate input to be hashed
        for i in range(32):
            flotsam_byte = ord(flotsam[i % len(flotsam)])
            dec_byte = seed[i] ^ flotsam_byte

            jetsam_byte = ord(jetsam[i % len(jetsam)])
            dec_byte -= jetsam_byte

            if dec_byte < 0:    # Negative bytes do not make sense
                break

            decrypted_input += hex(dec_byte)[2:]

        try:
            decrypted_input = binascii.unhexlify(decrypted_input)
        except binascii.Error:
            continue

        # Check for match
        hash = md5(decrypted_input).hexdigest()
        if hash == '6c5215b12a10e936f8de1e42083ba184':  # target hash
            print('>'*15, 'CRACKED', '<'*15)
            print(decrypted_input)
            print(flotsam, jetsam)
            break

def main():
    generate_combinations(flotsam_combs, ['DFWEyEW', 'PXopvM', 'BGgsuhn'])
    generate_combinations(jetsam_combs, ['newaui',  'HwdwAZ', 'SLdkv'])

    f_len, j_len = len(flotsam_combs), len(jetsam_combs)

    print(f'{f_len} * {j_len} = {j_len * f_len}')
    generate_meta_combinations(f_len if f_len > j_len else j_len)

    crack()


main()
```

Flag = `s1gn_my_gu357_b00k@flare-on.com`

## Challenge 5 — FLARE Linux VM
- 29 encrypted files, each 1024 bytes long (1 KB)
- last 847 bytes are identical for all files
	- start: `80 6A 87`
	- end: `85 C6 76`
- custom RC4 implementation found in the `zyppe` binary with hardcoded key ("A secret...")
- using IDA Pro's dissassembly output, reimplement in Python and decrypt each of the files

```python
import binascii
from os import listdir
from os.path import isfile, join


def decrypt(key, data):
    i = 0
    S = [i for i in range(256)]

    # KSA
    for j in range(256):
        i = (i + S[j] + ord(key[j % len(key)])) % 256
        S[j], S[i] = S[i], S[j]

    i = j = XORed = 0
    output = ''

    # Non-standard PRGA
    for k in range(len(data)):
        j = (j + 1) % 256
        i = (i + S[j]) % 256
        S[j], S[i] = S[i], S[j]

        val = S[(S[i] + S[j]) % 256]
        output += chr(data[k] ^ val ^ XORed)  # <-- CUSTOM
        #         chr(data[k] ^ val)          # <-- standard
        XORed = val

    return output.encode()


def main():
    passphrase = "A secret is no longer a secret once someone knows it"

    files = sorted([
        f for f in listdir('samples') if isfile(join('samples', f))
    ])

    for file in files:
        with open(f'samples/{file}', 'rb') as fd:
            data = fd.read()

        output = decrypt(passphrase, data)

        print(output)
        print('-'*80)


main()
```

Byte-pattern showing up on all files:

```
44 7C 07 A8 23 FD C7 D4 64 E8 4B BE DA 86
72 97 AE 15 5C 77 AA 83 89 98 E8 23 35
37 23 8D 0C 92 D4 B4 5C B5 24 CC 43 BE 74 D6 9C C5 28
```

`.bashrc` contents:

```bash
alias FLARE="echo 'The 13th byte of the password is 0x35'"
```

`.bash_profile` contents

```bash
export NUMBER1=2
export NUMBER2=3
export NUMBER3=37
```

`crontab -l` output:

```bash
* * * * * /usr/lib/zyppe
```

### Decrypted files

#### backberries.txt.broken
```
1b03450a0a5253331700530b480772020a1c01071a3c450812114f007e45111b00071c3c091c53114f1a3c0245070d46077206041d4554122400450a0a52533b1645070a0711374504530746003a45000b154201264b453c114f1620120c0000070a3d1045040c4b1f72070053094810390001530d42013745031c1742053717453b24073b13452d32442d

--> XOR Reese's
	If you are not good in maths, the only thing that can save you is to be a bash expert. Otherwise you will be locked here forever HA HA HA!
```

#### banana_chips.txt.broken
```
131700531c480672020a1c01071226450812114f006d453216454b1c2400451e04531b2145040745613f133720524570167210161645531b3b1645150a551e2709045304071f3d1145070a071737060a170007112b1100005f0751172b263c2162370d273c27200758725752534e073d0728273637165378452b262865360057455e4569261f272021560579

--> XOR Reese's
	Are you good at maths? We love maths at FLARE! We use this formula a lot to decode bytes: "ENCODED_BYTE + 27 + NUMBER1 * NUMBER2 - NUMBER3"

--> substitute with bash aliases
	ENCODED_BYTE + 27 + 2 * 3 - 37
	ENCODED_BYTE - 4
```

#### blue_cheese.txt.broken
```
060d005351531b72071c0700071c3445111b000703331616040a5517720c164945170b61506f

--> XOR Reese's
	The 4th byte of the password is: 0x35
```

#### .daiquiris.txt.broken
```
Qac 7ys hcpe xq cyp typxterl xi: 0m66

--> Bifid "eggs"
	The 7th byte of the password is: 0x66
```

#### donuts.txt.broken
```
Din moq agos etcp Ememog Lhobeihz Awttivt ytxtv drwvgoswps?

--> Bifid "eggs"
	Did you know that Giovan Battista Bellaso loved microwaves?
```

#### dumplings.txt.broken
```
Abn lef emadkxp frceqdnhe? Tah gdcktm temyku xxo qo ktyhzn! Zd'k raooua, por uda ztykqh.

--> Bifid "eggs"
	Are you missing something? You should search for it better! It's hidden, but not really.
```

#### iced_coffee.txt.broken
```
586c69247372707d2474767366706971247b6d786c24564738246d7724786c6578247d737924726969682465246f697d3224586c69244a50455649247869657124727376716570707d247977697724786c6d77247279716669763e24265756494a464926242c65772465722459584a313c247778766d726b2d32244d6a247d7379246c657a69247273246d686965247b6c657824786c657824716965727730247d737924776c73797068246b6d7a69247974246572682466656f6924777371692471796a6a6d7277320e

--> ENC_BYTE - 4
	The only problem with RC4 is that you need a key. The FLARE team normally uses this number: "SREFBE" (as an UTF-8 string). If you have no idea what that means, you should give up and bake some muffins.
--> substitute
	"SREFBE" -> "493513"
```

#### ice_cream.txt.broken
```
4d6a24786c6d7724676c65707069726b69246d772478737324686d6a6a6d6779707824657268247d7379247b657278247873246b6d7a69247974247376246e797778246d722467657769247d7379246b7378246c79726b767d30247b6c65782465667379782466656f6d726b24777371692471796a6a6d7277432458767d24786c6d77247669676d74693e0e34243124476d7272657173720e35243124467978786976243539346b760e362431245069717372243533360e37243124496b6b7724370e3824312457796b6576243539346b760e392431244a70737976243639346b760e3a243124516d706f2437346b760e3b2431244d676d726b2477796b65762435346b760e3c2431244574747069243534346b760e3d24312456657774666976766d6977243534346b760e0e516d7c2434247873243d246572682466656f69246a737624373424716d727978697724657824353c34c386c2b447320e0e

--> ENC_BYTE - 4
	If this challenge is too difficult and you want to give up or just in case you got hungry, what about baking some muffins? Try this recipe:
	0 - Cinnamon
	1 - Butter 150gr
	2 - Lemon 1/2
	3 - Eggs 3
	4 - Sugar 150gr
	5 - Flour 250gr
	6 - Milk 30gr
	7 - Icing sugar 10gr
	8 - Apple 100gr
	9 - Raspberries 100gr

	Mix 0 to 9 and bake for 30 minutes at 180°C.
```

#### instant_noodles.txt.broken
```
586c692439786c24667d786924736a24786c6924746577777b737668246d773e24347c51570e

--> ENC_BYTE - 4
	The 5th byte of the password is: 0xMS
--> substitute
	0xMS -> 0x64
```

#### nachos.txt.broken
```
48c3a6c29dc2bac39dc3bdc385c381c3a2c2b5c3afc28a4615c3967bc3b8c2a82809c3aa72442051c3a64ec2b629c28a6a3bc29c642bc3bac2a7c3b6c2b012c297c3875642c29d65c3abc286c3ac675ec38c675c22c395c3b214503ec3b41843c391c2a4c2bbc2ae753a55c2a331441e22194d744cc3b966c3860b22c3b2022c7901c2b56b2a41c28ac28ec385c3a1c29c68c2a50e39c2ad1043c3b50cc2a4c2a565c38210c39fc3b30448c39750123bc2bf457bc382c2ad73c382c297c3827e59c2b9c286c2a420c3a7c3bb06c38f33c2b0c38b46c3be13c39831c2ac1bc2adc2920d7ac2a1c2bcc389c39ec2a9c2a80951c28d5053c388c29cc298c3a572c393285bc2afc2b4c2952ec29756c2b24c

--> RC4 "493513"
	In the FLARE team we really like Felix Delastelle algorithms, specially the one which combines the Polybius square with transposition, and uses fractionation to achieve diffusion.
```

#### natillas.txt.broken
```
45c3a7c29dc2b7c39ac3adc385c3acc380c29bc38ac3af0800c38773c3b9c3a43e1fc3b520682f1dc39947c3b72cc28d2d7ec3884a27c3a5c3aec3bac3b524c29fc28b4554c28f65c3b5c299c2a93350c280611333c389c3b5085c3fc2bc1854c388c2b2c2b0c3a779375dc2bf31471f3351027740c2b57ac28e032fc3be02045335c2804d1660c395c28ec382c3a0c29421c2990027c3b40645c2a010c3b0c2be71c38551c3a8c3a35650c38e411b75c3ab5468c389c2bf6ec39ec384c38a7910c2b5c29a606dc3a3c2b503c28121c2afc38f5cc2ad10c28470c28601c3a4c2be0c77c2bac2b8c384c399c3a8c3b04605c284561bc385c29cc282c3a931c3962244c3a9c2a5c28922c28b18c3b229c3a649c3a745c39fc3b768c2bec39741c3aec2a3c3a5c28ec3b8c2b93b18c3a3c3924831c393c39dc29cc38ec3a9c2ae3ec2b56a104d255dc2b84732c2a5056660

--> RC4 "493513"
	Do you know natillas? In Spain, this term refers to a custard dish made with milk and KEYWORD, similar to other European creams as crème anglaise. In Colombia, the delicacy does not include KEYWORD, and is called natilla.
--> KEYWORD = eggs
```

#### nutella.txt.broken
```
55c3a0c398c3aec283c3acc28dc2a7c38cc28dc389c2aa460ec3953ac3a1c3a03a4cc2ba6152324ac3a545c3b265c28a7264c29c1236c2a5c3b8c284

--> RC4 "493513"
	The 6th byte of the password is: 0x36
```

#### oats.txt.broken
```
Kww jvkugh xatnfk phz JDMZG kswm dr Liqvksn. Tciq bwuk o xuigz an keharzwluvi jhqfa efp pcms crzel owpmsnsvxaav qe Hsioxwd!
pvkdo://trmlfmt.tci/aieeyi_06
jkhls://oaafbgi.qkm/HediitvAaccefu

--> VIGENERE MICROWAVES
	You should follow the FLARE team in Twitter. They post a bunch of interesting stuff and have great conversation on Twitter!
	https://twitter.com/anamma_06
	https://twitter.com/MalwareMechanic
```

#### omelettes.txt.broken
```
Kww jvkugh xatnfk phz JDMZG kswm dr Liqvksn. Oolwdekjs phzc emg ivh wnbvq mvf ecp lzx qac nvore zzwz qh pcq gzx ltm hcoc.
hoxhe://byzhpem.ggy/ipraia_06
cxlba://vnwptzv.uau/qjondvv1
zfbrj://hsioxwd.kqd/AwlrejqUgtvwndg

--> VIGENERE MICROWAVES
	You should follow the FLARE team in Twitter. Otherwise they may get angry and not let you leave even if you get the flag.  
	https://twitter.com/anamma_06  
	https://twitter.com/osardar1  
	https://twitter.com/MalwareMechanic
```

#### oranges.txt.broken
```
Fpg 8kv xyoi gr bjv dwsnagdl kj: 0l60

--> VIGENERE MICROWAVES
	The 8th byte of the password is: 0x60
```

#### raisins.txt.broken
```
VGhlIDNyZCBieXRlIG9mIHRoZSBwYXNzd29yZCBpcy4uIGl0IGlzIGEgam9rZSwgd2UgZG9uJ3QgbGlrZSByYWlzaW5zIQo=

--> Base64
	The 3rd byte of the password is.. it is a joke, we don't like raisins!
```

#### rasberries.txt.broken
```
VGhlIDNyZCBieXRlIG9mIHRoZSBwYXNzd29yZCBpczogMHg1MQo==

--> Base64
	The 3rd byte of the password is: 0x51
```

#### reeses.txt.broken
```
V2UgTE9WRSAiUmVlc2UncyIsIHRoZXkgYXJlIGdyZWF0IGZvciBldmVyeXRoaW5nISBUaGV5IGFyZSBhbWF6aW5nIGluIGljZS1jcmVhbSBhbmQgdGhleSBldmVuIHdvcmsgYXMgYSBrZXkgZm9yIFhPUiBlbmNvZGluZy4K

--> Base64
	We LOVE "Reese's", they are great for everything! They are amazing in ice-cream and they even work as a key for XOR encoding.
```

#### shopping_list.txt.broken
```
/
[U]don noodles
[S]trawberries
[R]eese's
/
[B]anana chips
[I]ce Cream
[N]atillas
/
[D]onuts
[O]melettes
[T]acos
```

#### sausages.txt.broken
```
2a34c2b21019c2b93a1031c2bc3ac2b210c2b733103a34c2b21038c2b0c2b9c2b9c2bbc2b7393210c2b4c2b910183cc2991a05

--> ROL 1
	The 2st byte of the password is 0x34
```

#### spaghetti.txt.broken
```
c2a437103a34c2b2102326c2a029c2a21036c2b037c2b3c2bac2b0c2b3c2b21011c2b938c2b0c2b334c2b23a3ac2b41110c2b4c2b91011c2b1c29921342d19343632242938111705

--> ROL 1
	In the FLARE language "spaghetti" is "c3BhZ2hldHRp".
	c3BhZ2hldHRp <base64-decode> spaghetti
```

#### strawberries.txt.broken
```
c2a437103a34c2b2102326c2a029c2a2103ac2b2c2b0c2b610c2bbc2b21036c2b4c2b5c2b2103ac2b710c2b938c2b2c2b0c2b510c2b43710c2b1c2b732c2b21710c2acc2b7c2ba10c2b934c2b7c2ba36321036c2b2c2b0393710c2b7c2ba391036c2b037c2b3c2bac2b0c2b3c2b21610c2b73a34c2b239c2bbc2b4c2b9c2b210c2bcc2b7c2ba10c2bbc2b0373a1031c2b210c2b03136c2b2103ac2b710c2b938c2b2c2b0c2b510c2bbc2b43a3410c2bac2b910c2bb34c2b23710c2bcc2b7c2ba10c2b2c2b9c2b1c2b038c2b21014c2b43310c2bcc2b7c2ba10c2b6c2b037c2b0c2b3c2b2103ac2b710c2b2c2b9c2b1c2b038c2b2c290c294171023c2b73910c2b23cc2b0c2b63836c2b21610c2b437c2b93ac2b2c2b03210c2b7331011c2b93a39c2b0c2bb31c2b23939c2b4c2b2c2b91110c2bbc2b210c2b9c2b0c2bc1011c2b1c29929c2bcc2ac2c32c2b42d2c25c2bcc2b0c2ab2b3d111705

--> ROL 1
	In the FLARE team we like to speak in code You should learn our language otherwise you want be able to speak with us when you escape (if you manage to escape!). For example instead of "strawberries" we say "c3RyYXdiZXJyaWVz".
	c3RyYXdiZXJyaWVz <base64-decode> strawberries
```

#### tacos.txt.broken (unsolved)
```
27420b6486cfe04e872b09e3bddaa76ef575e5ef36e8306db062e2febc6d6cab46b4a761b2c0c3ce6f405c7add12ce0ec7483fb83876f0ceb20345d0597a4d995a188abb8793a3e433a19a7631dad4070715bc752cff0db74fbc7a06d97abbd7895559f4c2d3c86ef5433ee7b2738c3f512d18e101b904ff173296d03671b739beb783f37eecd39e7822e67c04e300b01a74a8e8f4d6b7edd21d5af52366fba06147431e9f46fb21bf6de2f005f70529
```

#### tiramisu.txt.broken (unsolved)
```
aa68c1adcfb5bcb550b4d2e44da48bb59b1cc86701cb3df2b2c81bc468e3c710b6e6a07c1bce4a04b2a34192823aa0b64f883783170f6c21d00b20c4a44c6acfdc2c8ab757bee984ac75dabd0e3f2bc9c215adb2d7db63e018e8d6cf1738e577d3da898d5ee8eb3276e51cf035146af8b558e5fa91ed2ee98e6795a7317569fcf77eb1cb679ae54c7b06db795ecd6c3a23862043a8938cf2733ab3ebd771e59dbde60e677c40491e1ccab3e792097d2f13389646ace071ed0494387506a077d5f4c0901793003dd8b3038f445305ea363006e7668913804b89e17dcef2fb4b3d96e77a444bdfacf82263f451ed4ddd79f38cf3b317ba759bec5405876723dcf4e08786deacd6ad34c97889f8c588263602a534f1e94b356d37e0d853ae50da18ef2752e105d1fd98697a72172c1c672b2e652290b558a3d20ae21d85f048444acf77c51e8c942aef341937227e517e7bac3c6710c5613a45f5767d675b856ebabe9f95115f1932e479e4fda350f7b8f621df84073672544080b70ca5607fd89e32691c2d06fee5354a23ecd156ccda9f0940bef01ded4d55ca7342016425b5ba00dee06d1f26307ea8fc4667a6772ddc
```

#### tomatoes.txt.broken (unsolved)
```
4892fbcc38c4a6aeeb2435081ec6cd83535b7f4e1ded18ad2a1ba9d5c5f825a6e53b343b0a04d39bf4c1fde228d0d958abea262bc8b4e5ac8eda08908be43e0354cf0bd78a3bbc23149776da6fdb4d4118f8095540113a2719e41308305727ac02831d3018e853d96b0f9d22e2866bff32b5565e2510e5dc25ac0b605fc929767d17f346c091cf91cd28c3ab0efa13b528aae1a7c2239e0348da44e0b814a80b8fded988f9bf3d1aee36ef42597767a41d2adb8ad7464cd5f248391665fc3dee05f0174bb0e5e8b5b3c26e021212e60a3f6462bcd04eba4a37ad2e76a07fdad2a00f02f7c4ac6cb825e5a98be1e6390b1d3bf481e1f79fb1ecf6a5dfce1e9615db51e51de7a48832a6bec04c3756b0b8
```

#### udon_noddles.txt.broken
```
"ugali", "unagi" and "udon noodles" are delicious. What a coincidence that all of them start by "u"!
```

#### ugali.txt.broken
```
Ugali with Sausages or Spaghetti is tasty. It doesn't matter if you rotate it left or right, it is still tasty! You should try to come up with a great recipe using CyberChef.
```

#### unagi.txt.broken
```
The 1st byte of the password is 0x45
```

Letter | Count | Decrypted | Cipher
------ | ----- | ------- | ----
`b` | 3 | ✅ | XOR "Reese's"
`d` | 3 | ✅ | Bifid "eggs"
`i` | 3 | ✅ | ENC_BYTE - 4
`n` | 3 | ✅ | RC4 "493513"
`o` | 3 | ✅ | Vigenere "microwaves"
`r` | 3 | ✅ | Base64
`s` | 4 | ✅ | ROL 1
`t` | 3 | ❌ | ???
`u` | 3 | ✅ | Plaintext

### Password
`0x45 0x34 0x51 0x35 0x64 0x36 0x66 0x60 ? ? ? ? 0x35 ?`
```E4Q5d6f`????5```

SHA256 hash from `/usr/bin/dot` binary: ==b3c20caa9a1a82add9503e0eac43f741793d2031eb1c6e830274ed5ea36238bf==

Tried bruteforcing with 13 bytes, didn't work
Guess length is 14 bytes
Bruteforced 5 unknown bytes with custom script (reduced time by assuming ASCII):

```python
from hashlib import sha256


def main():
    target = 'b3c20caa9a1a82add9503e0eac43f741793d2031eb1c6e830274ed5ea36238bf'
	# TODO: change and test with 127
    for i in range(256):
        print(f"[*] {i}...")
        i = chr(i)
        for j in range(256):
            j = chr(j)
            for k in range(256):
                k = chr(k)
                for l in range(256):
                    l = chr(l)
                    for m in range(256):
                        m = chr(m)
                        plaintext = f"E4Q5d6f`{i}{j}{k}{l}5{m}"
                        _hash = sha256(plaintext.encode()).hexdigest()

                        if target == _hash:
                            print(f"[!] CRACKED >>> {plaintext}")
                            return


main()
```

- Cracked password: ```E4Q5d6f`s4lD5I```
- Input password in `/usr/bin/dot` (see `shopping_list.txt.broken`)

Flag: `H4Ck3r_e5c4P3D@flare-on.com`

## Challenge 6 — FLARE Linux VM (unsolved)
- PCAP traffic capture
- Extracted PNG file (cat picture) with Wireshark
- Found `PA30` header --> Windows **delta patch** file

### TCP conversations
Source | Src port | Destination | Dst port | Artifact
------ | -------- | ----------- | -------- | --------
`172.16.111.139` | 2020 | `172.16.111.144` | 1337 | PNG
`172.16.111.139` | 2021 | `172.16.111.144` | 1337 | ?


## Meta
- #flareon
- #ctf
- #re
- #malware
- #crypto
