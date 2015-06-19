# decrypt\_bitcoinj\_seed.pyw #

 * a simple Python script which decrypts and displays the seed mnemonic from from a bitcoinj-based HD wallet file
 * supported on Windows and Linux
 * currently supports:
     * [MultiBit HD](https://beta.multibit.org/) (mbhd.wallet.aes files)
     * [Bitcoin Wallet for Android 4.x](https://play.google.com/store/apps/details?id=de.schildbach.wallet) wallet files (requires root)
     * [Bitcoin Wallet for Android 4.x](https://play.google.com/store/apps/details?id=de.schildbach.wallet) encrypted backup files

## Warning ##

Working with an unencrypted seed is risky. If you are uncertain whether or not your computer is completely free of malware, you should not run this nor any other program that can affect your finances.

Even if you are certain you are currently free of malware, it is strongly advised that you not store an unencrypted seed to your hard drive.

## Installation ##

Just download the latest version from <https://github.com/gurnec/decrypt\_bitcoinj\_seed/archive/master.zip> and unzip it to a location of your choice. There’s no installation procedure for the Python script itself, however there are additional requirements below depending on your operating system.

### Windows ###

 * The latest version of Python 2.7, either the 32-bit version or the 64-bit version. Currently this is Python 2.7.10, either the “Windows x86 MSI installer” for the 32-bit version, or the “Windows x86-64 MSI installer” for the 64-bit version (which is preferable if you have a 64-bit version of Windows), both available here: <https://www.python.org/download/>
 * Google Protobuf and pylibscrypt for Python – choose one of the following two installation methods:
     * Automated installation: right-click on the included *install-windows-requirements.ps1* file and choose *Run with Powershell*. Automated installation typically only works with Windows Vista SP1 and higher (including Windows 7+), but it doesn't hurt to try with other versions of Windows.
     * Manual installation:
         1. You must have Python 2.7.9 or later (or you must [manually install Python pip](https://pip.pypa.io/en/latest/installing.html#install-pip)).
         2. Open a command prompt (Start -> Run, type `cmd` and click OK).
         3. Type this at the command prompt: `C:\Python27\Scripts\pip install protobuf pylibscrypt`, and then press the `Enter` key.

### Linux ###

 * Python 2.7.x – most distributions include this pre-installed.
 * Tkinter for Python – some distributions include this pre-installed, check your distribution’s package management system to see if this is available. It is often called “python-tk”.
 * Google Protobuf and pylibscrypt for Python - use PyPI, for example on Debian-like distributions:

        sudo apt-get install python-pip
        sudo pip install protobuf pylibscrypt

Before running decrypt\_bitcoinj\_seed.pyw for the first time, you must enable the execute permission on the file (right click -> Properties, or use `chmod` at the command line).

## How to Use ##

Simply double-click decrypt\_bitcoinj\_seed.pyw and choose your wallet file in the file selection dialog. Please note that some wallet files may take several minutes to decrypt (if you don't have [one of the optional libraries](https://pypi.python.org/pypi/pylibscrypt/1.3.0#requirements) installed).

## Credits ##

Third-party libraries distributed with decrypt\_bitcoinj\_seed.pyw include:

 * aespython, please see [aespython/README.txt](aespython/README.txt) for
 more information

 * bitcoinj wallet protobuf, please see [wallet.proto](wallet.proto)
 for more information
