#!/usr/bin/python

# extract-bitcoinj-seed.py
# Copyright (C) 2014 Christopher Gurnee
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# 1. Redistributions of source code must retain the above copyright
# notice, this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright
# notice, this list of conditions and the following disclaimer in the
# documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
#  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

# If you find this program helpful, please consider a small
# donation to the developer at the following Bitcoin address:
#
#           1Lj3kXWTuYaRxvLndi6VZKj8AYa3KP929B
#
#                      Thank You!

from __future__ import print_function

__version__ =  '0.2.1'

import hashlib, sys, getpass
import aespython.key_expander, aespython.aes_cipher, aespython.cbc_mode
import wallet_pb2

sha256 = hashlib.sha256
md5    = hashlib.md5


key_expander = aespython.key_expander.KeyExpander(256)

def aes256_cbc_decrypt(ciphertext, key, iv):
    """decrypts the ciphertext using AES256 in CBC mode

    :param ciphertext: the encrypted ciphertext
    :type ciphertext: str
    :param key: the 256-bit key
    :type key: str
    :param iv: the 128-bit initialization vector
    :type iv: str
    :return: the decrypted ciphertext, or raises a ValueError if the key was wrong
    :rtype: str
    """
    block_cipher  = aespython.aes_cipher.AESCipher( key_expander.expand(map(ord, key)) )
    stream_cipher = aespython.cbc_mode.CBCMode(block_cipher, 16)
    stream_cipher.set_iv(bytearray(iv))
    plaintext = bytearray()
    for i in xrange(0, len(ciphertext), 16):
        plaintext.extend( stream_cipher.decrypt_block(map(ord, ciphertext[i:i+16])) )
    padding_len = plaintext[-1]
    # check for PKCS7 padding
    if not (1 <= padding_len <= 16 and plaintext.endswith(chr(padding_len) * padding_len)):
        raise ValueError('incorrect password')
    return str(plaintext[:-padding_len])


def load_wallet(wallet_file, get_password_fn):
    """load and if necessary decrypt (OpenSSL style) a bitcoinj wallet file

    :param wallet_file: an open bitcoinj wallet file
    :type wallet_file: file
    :param get_password_fn: a callback returning a password that's called iff one is required
    :type get_password_fn: function
    :return: the Wallet protobuf message or None if no password was entered when required
    :rtype: wallet_pb2.Wallet
    """

    # Check to see if this is an encrypted (OpenSSL style) wallet backup
    wallet_file.seek(0)
    magic_bytes = wallet_file.read(12)
    try:
        is_encrypted = magic_bytes.decode('base64').startswith(b'Salted__')
    except Exception:
        is_encrypted = False
    wallet_file.seek(0)

    if is_encrypted:
        ciphertext = wallet_file.read().decode('base64')
        assert len(ciphertext) % 16 == 0

        password = get_password_fn()
        if not password:
            return None

        # Derive the encryption key and IV
        salted_pw = password.encode('UTF-8') + ciphertext[8:16]
        key1 = md5(salted_pw).digest()
        key2 = md5(key1 + salted_pw).digest()
        iv   = md5(key2 + salted_pw).digest()

        # Decrypt the wallet
        plaintext = aes256_cbc_decrypt(ciphertext[16:], key1 + key2, iv)

    else:
        plaintext = wallet_file.read()

    # Parse the wallet protobuf
    pb_wallet = wallet_pb2.Wallet()
    try:
        pb_wallet.ParseFromString(plaintext)
    except Exception as e:
        raise ValueError('not a wallet file: ' + str(e))
    return pb_wallet


def extract_mnemonic(pb_wallet, get_password_fn):
    """extract and if necessary decrypt (w/scrypt) a BIP39 mnemonic from a bitcoinj wallet protobuf

    :param pb_wallet: a Wallet protobuf message
    :type pb_wallet: wallet_pb2.Wallet
    :param get_password_fn: a callback returning a password that's called iff one is required
    :type get_password_fn: function
    :return: the first BIP39 mnemonic found in the wallet or None if no password was entered when required
    :rtype: str
    """
    for key in pb_wallet.key:
        if key.type == wallet_pb2.Key.DETERMINISTIC_MNEMONIC:

            if key.HasField('secret_bytes'):      # if not encrypted
                return key.secret_bytes

            elif key.HasField('encrypted_data'):  # if encrypted (w/scrypt)
                import pylibscrypt

                # Derive the encryption key
                aes_key = pylibscrypt.scrypt(
                    get_password_fn().encode('utf_16_be'),
                    pb_wallet.encryption_parameters.salt,
                    pb_wallet.encryption_parameters.n,
                    pb_wallet.encryption_parameters.r,
                    pb_wallet.encryption_parameters.p,
                    32)

                # Decrypt the mnemonic
                ciphertext = key.encrypted_data.encrypted_private_key
                iv         = key.encrypted_data.initialisation_vector
                return aes256_cbc_decrypt(ciphertext, aes_key, iv)

    else:  # if the loop exists normally, no mnemonic was found
        raise ValueError('no BIP39 mnemonic found')


def find_unextracted(pb_wallet):
    """search for non-BIP32 keys or extra BIP39 mnemonics
    :param pb_wallet: a Wallet protobuf message
    :type pb_wallet: wallet_pb2.Wallet
    :return: a warning string if found, else ''
    :rtype: str
    """
    nonbip32_count = mnemonic_count = unknown_count = 0
    for key in pb_wallet.key:
        if key.type == wallet_pb2.Key.ORIGINAL or key.type == wallet_pb2.Key.ENCRYPTED_SCRYPT_AES:
            nonbip32_count += 1
        elif key.type == wallet_pb2.Key.DETERMINISTIC_MNEMONIC:
            mnemonic_count += 1
        elif key.type == wallet_pb2.Key.DETERMINISTIC_KEY:
            pass  # ideally we would check that these derive from the mnemonic
        else:
            unknown_count += 1

    warning_msg = ''
    if nonbip32_count:
        warning_msg += str(nonbip32_count) + ' non-deterministic keys found.\n'
    if mnemonic_count > 1:
        warning_msg += str(mnemonic_count-1) + ' extra mnemonics found.\n'
    if unknown_count:
        warning_msg += str(unknown_count) + ' unknown key types found.\n'
    if warning_msg:
        warning_msg += 'Your mnemonic backup does NOT back up your entire wallet.'
    return warning_msg


if __name__ == '__main__':

    padding      = 6     # GUI widget padding
    progress_bar = None  # GUI progress bar

    # command-line specific code
    if len(sys.argv) > 1:

        if len(sys.argv) != 2 or sys.argv[1].startswith('-'):
            sys.exit('usage: decrypt_bitcoinj_seed.pyw bitcoinj-wallet-file')

        wallet_file = open(sys.argv[1], 'rb')

        def get_password_factory(prompt):
            def get_password():  # must return unicode
                encoding = sys.stdin.encoding or 'ASCII'
                if 'utf' not in encoding.lower():
                    print('terminal does not support UTF; passwords with non-ASCII chars might not work', file=sys.stderr)
                password = getpass.getpass(prompt + ' ')
                if isinstance(password, str):
                    password = password.decode(encoding)  # convert from terminal's encoding to unicode
                return password
            return get_password

        # These functions differ between command-line and GUI runs
        get_password  = get_password_factory('This wallet backup is encrypted, please enter its password:')
        get_pin       = get_password_factory("This wallet's seed is encrypted with a PIN or password, please enter it:")
        display_error = lambda(msg): print(msg, file=sys.stderr)

    # GUI specific code
    else:

        import Tkinter as tk, ttk, tkFileDialog, tkSimpleDialog, tkMessageBox

        root = tk.Tk(className='Bitcoinj Key Deleter')  # initialize the library
        root.withdraw()                                 # but don't display a window yet

        wallet_file = tkFileDialog.askopenfile('rb', title='Load wallet file')
        if not wallet_file:
            sys.exit('no wallet file selected')

        # Initializes the main window and displays a progress bar
        def init_window(no_progress = False):
            global progress_bar
            if not progress_bar:
                tk.Label(text='WARNING: seed information is sensitive, carefully protect it and do not share', fg='red').pack(padx=padding, pady=padding)
                tk.Label(text='decrypted seed mnemonic:').pack(side=tk.LEFT, padx=padding, pady=padding)
                if not no_progress:
                    progress_bar = ttk.Progressbar(length=480, orient='horizontal', mode='indeterminate')
                    progress_bar.pack(side=tk.LEFT, padx=padding, pady=padding)
                root.deiconify()
            root.update()

        # These functions differ between command-line and GUI runs
        def get_password():  # must return Unicode
            password = tkSimpleDialog.askstring('Password', 'This wallet backup is encrypted, please enter its password:', show='*')
            return password.decode('ASCII') if isinstance(password, str) else password
        def get_pin():       # must return Unicode
            pin = tkSimpleDialog.askstring('Password', "This wallet's seed is encrypted with a PIN or password, please enter it:", show='*')
            init_window()    # display the progress bar -- this may take a while if there are no binary scrypts installed
            return pin.decode('ASCII') if isinstance(pin, str) else pin
        def display_error(msg):
            return tkMessageBox.showerror('Error', msg)

    # Load (and possibly decrypt) the wallet, retrying on bad passwords
    while True:
        try:
            wallet = load_wallet(wallet_file, get_password)
            if not wallet:  # if no password was entered
                exit(1)
            break
        except ValueError as e:
            if e.args[0] != 'incorrect password':
                raise
            display_error(str(e))

    # Extract (and possibly decrypt) the mnemonic, retrying on bad passwords
    while True:
        try:
            mnemonic = extract_mnemonic(wallet, get_pin)
            if not wallet:  # if no password was entered
                exit(1)
            break
        except ValueError as e:
            if e.args[0] != 'incorrect password':
                raise
            display_error(str(e))

    extra_keys_warning = find_unextracted(wallet)

    # command-line specific code
    if len(sys.argv) > 1:
        if extra_keys_warning:
            print('\nWARNING:')
            print(extra_keys_warning)
        print('\nWARNING: seed information is sensitive, carefully protect it and do not share')
        print('decrypted seed mnemonic:\n', mnemonic)

    # GUI specific code
    else:

        if extra_keys_warning:
            tkMessageBox.showwarning('Warning', extra_keys_warning)

        # Create the text box that will hold the mnemonic
        entry = tk.Entry(width=80, readonlybackground='white')
        entry.insert(0, mnemonic)
        entry.config(state='readonly')
        entry.select_range(0, tk.END)

        # Replace the progress bar if the window already exists; else init the window
        if progress_bar:
            progress_bar.pack_forget()
        else:
            init_window(no_progress=True)
        entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=padding, pady=padding)

        root.deiconify()
        entry.focus_set()
        root.mainloop()
