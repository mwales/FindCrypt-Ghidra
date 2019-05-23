# What is different about my fork

* Removed autoupdate features.
* Outputs results to Ghidra console, just click the addresses to view them in
  code browser
* Changed some of the installation paths

# FindCrypt - Ghidra Edition

While for years we used IDA Pro and its incredible plugins developed by its huge community, Ghidra came out recently (at the time of writing) showing a lot of potential and an incredible modular design for customization both in Python or Java.

As most of you know, FindCrypt, a plugin made by nonetheless than Ilfak Guilfanov himself for IDA, is essential for quickly find references to Cryptography functions in the target and extremely useful in the field of Reverse Engineering.

I'm trying to move to Ghidra and the very first thing I noticed is how important is the plugin to me, so I took the responsibility to migrate it, in Java, without sacrificing any signature and try to improve it as well.

![Demo](https://github.com/d3v1l401/FindCrypt-Ghidra/blob/master/Misc/demo.gif)

**This software is being developed and tested, if you encounter any problem please proceed into the Issues section**

## Installation

#### Windows

Windows?  Blech...

#### Linux

1. Find your Ghidra installation directory (e.g. ~/ghidra)
2. Move "FindCrypt.java" and database.dv3 into "~/ghidra_scripts/"

## Usage

Once you started your project and opened the disassembler, use the Script Manager window and search for "FindCrypt.java",
by double clicking or pressing "Run" will execute the script and a result screen is shown if something is found.

![Example result](https://github.com/d3v1l401/FindCrypt-Ghidra/blob/master/Misc/resDemo.png)

### Database

The database is a binary file I serialized myself, it's very easy to understand and very basic but functional for its goal.
The database contains all of the **79** algorithms constants implemented by Ilfak, no sacrifices have been made while migrating them, while also adding more and more by the contributors.


There's a total of **122 detectable constants** in the database, related to:

* **Raw Primitives**
	* Keccak (SHA-3)
* **Elliptic Curves**
	* Donna32 (EC25519), Donna64 (EC25519)
* **Stream ciphers** 
    * Chacha, Salsa, Sosemanuk
* **Block ciphers**
    * Blowfish, Camellia, DES, TripleDES, RC2, SHARK, Cast, Square, WAKE, Skipjack, HIGHT, Kalyna, LEA, SEED, SCHACAL2, SIMON-64, SIMON-128, TEA/TEAN/XTEA/XXTEA
* **Hash funcions** 
    * Whirlpool, MD2, MD4, MD5, SHA-1, SHA-256, SHA-384, SHA-512, Tiger, RIPEMD160, HAVAL, BLAKE2
* **AES Family**
    * AES, RC5/RC6, MARS, Twofish, CAST-256, GOST, SAFER 
* **Compression** 
    * ZLib 

To include more constants of your choice, simply refer to the "FCExporter" project and perhaps also share your new entries :)

#### Database Updating

git pull

#### Script Updating

Nope...

# Credits
d3vil401 - d3vil401@protonmail.com, d3vil401#7685 (Discord), https://d3vsite.org/

Ilfak Guilfanov - https://twitter.com/ilfak

NSA (Ghidra) - https://ghidra-sre.org/

![Ghidra Logo](https://media.defense.gov/2019/Mar/05/2002096238/400/400/0/190503-D-IM742-3002.PNG)

### License

GNU GPLv3 - Refer to "LICENSE"

Using Crypto++ - Refer to Licenses\Crypto++.txt
