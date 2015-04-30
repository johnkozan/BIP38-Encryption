'use strict';

var assert = require('assert');
var bs58check = require('bs58check');
var buffer = require('buffer');
var crypto = require('crypto');
var sha512 = require('sha512');

function Bip32Encryption() {
  if (!(this instanceof Bip32Encryption)) return new Bip32Encryption();
}

/**
 * makeWallet - Seraizlie a BIP-32 root key and creation date with optional encryption
 *
 * @param {string} rootKey - a BIP 0032 root key. It should be a 16/32/64-byte string.
 * @param {number} date - Number of weeks since January 1, 2013
 * @param {string} [passphrase] - Passphrase to encrypt root key
 * @param {string} [fakePassphrase] - A second password which will also decrypt the root key to a different address
 * @param {number} [kdfFunctionIndex=0] - KDF function per spec. Accepted values: 0,1,2,8,9
 * @param {string} [fakePassphrase] - A second password which will also decrypt the root key to a different address
 * @param {string} [saltEntropy] - entropy used for encryption. Randomly generated if not given.
 * @returns {string}  Base58Check encoded serialized (an optionally encrypted) root key
 */
Bip32Encryption.prototype.makeWallet = function(rootKey, date, passphrase, fakePassphrase, kdfFunctionIndex, saltEntropy) {
  // TODO:
  // Allow rootKey Buffer or string to be passed in
  // Verify rootKey is valid bip32 rootkey
  // Date must be > 0
  // password defaults to ""
  // fakepassword defaults to ""
  // kdfFunctionIndex defaults to 0
  // saltEntrypy generate if required

  // Convert rootKey to buffer here unless it already is!
  var rootKeyBuffer = new Buffer(rootKey, 'hex');

  if ([16, 32, 64].indexOf(rootKeyBuffer.length) < 0) {
    throw new Error('Root Key must be 16, 32 or 64 byte string');
  }

  if (passphrase === undefined) {
    return makeUnencryptedWallet(rootKeyBuffer, date);
  } else {
    //return makeEncryptedWallet(rootKeyBuffer, date, kdfFunctionIndex, passphrase, fakePassphrase, saltEntropy);
  }
};

/**
 * decryptWallet - Deserialize an encrypted BIP-32 root key
 *
 * @param {string} encryptedWallet - an encrypted serialized BIP-32 root key, begins with RK or rk
 * @param {string} [passphrase] - Passphrase to decrypt root key, if it is encrypted
 * @returns {{rootKey: string, date: Number}}
 */
Bip32Encryption.prototype.decryptWallet = function(encryptedWallet, passphrase) {
  // TODO: Convert encrypted wallet to Buffer if not already
  var encryptedWalletBuffer = bs58check.decode(encryptedWallet);
  var prefix = encryptedWalletBuffer.slice(0, 2);

  //This dictionary maps prefixes to (wallet length, entropy length, is encrypted)
  // See the BIP spec for a better explanation. Look at the "prefixes" section.
  var prefixValues = {
    '28c1': [24, 0, false],
    '4ac5': [40, 0, false],
    'fbb3': [72, 0, false],
    'f83f': [26, 2, true],
    '6731': [43, 3, true],
    '4eb4': [76, 4, true]
  };

  var walletValues = prefixValues[prefix.toString('hex')];
  var walletLen, entropyLen, isEncrypted;
  if (walletValues === undefined) {
    throw new Error('Unknown wallet type: ' + prefix.toString('hex'));
  } else {
    walletLen = walletValues[0];
    entropyLen = walletValues[1];
    isEncrypted = walletValues[2];
  }

  if (encryptedWalletBuffer.length != walletLen)
    throw new Error('Length of encrypted wallet does not match length specified in prefix');

  if (!isEncrypted) {
    // [2 byte prefix][2 byte date][4 byte checksum][16/32/64 byte key, per prefix]
    var date = encryptedWalletBuffer.slice(2, 4);
    var checksum = encryptedWalletBuffer.slice(4, 8);
    var rootKey = encryptedWalletBuffer.slice(8, walletLen);

    if (secretChecksum(rootKey).slice(0, 4).toString('hex') != checksum.toString('hex'))
      throw new Error('Checksum mismatch. Ensure the wallet was entered correctly');

    return {
      rootKey: rootKey.toString('hex'),
      date: date.readUInt16LE(0)
    };
  }

  return '';
};

//Create a wallet with no encryption.
function makeUnencryptedWallet(rootKey, date) {
  // TODO: Make sure rootKey is buffer
  var bytePrefix;
  switch (rootKey.length) {
    case 16:
      bytePrefix = new Buffer([0x28, 0xC1]);
      break;
    case 32:
      bytePrefix = new Buffer([0x4A, 0xC5]);
      break;
    case 64:
      bytePrefix = new Buffer([0xFB, 0xB3]);
      break;
  }

  var checksum = secretChecksum(rootKey).slice(0, 4);
  var byteDate = new Buffer(2);
  byteDate.writeUInt16LE(date, 0);

  // should be 40 bytes: [2 version bytes] [ 2 date bytes] [4 checksum bytes?] [32 root key bytes]
  var buf = Buffer.concat([bytePrefix, byteDate, checksum, rootKey]);

  return bs58check.encode(buf);
}

// generates checksum, sha256 x2 of BIP-32 root key
function secretChecksum(data) {
  var secret = generateMasterSecret(data);

  var sha256a = crypto.createHash('sha256');
  sha256a.update(secret);

  var sha256b = crypto.createHash('sha256');
  sha256b.update(sha256a.digest());

  return sha256b.digest();
}

//root_key is a BIP 0032 root key. It should be a string.
//The returned value is a valid Bitcoin private key, in byte string format.
function generateMasterSecret(rootKey) {
  var I = sha512.hmac('Bitcoin seed').finalize(rootKey); // See BIP 0032. This is used to generate the master secret and master chain.
  var masterSecretBuffer = I.slice(0, 32); // The value of the master secret, as a string
  var masterSecret = masterSecretBuffer.readInt32BE(0); //int(master_secret_string.encode('hex'), 16); // The integer value of the master secret
  var curveOrder = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
  if (masterSecret === 0 || masterSecret >= curveOrder)
    throw new Error('Specified root key generates invalid secret');

  return masterSecretBuffer;
}

module.exports = Bip32Encryption;
