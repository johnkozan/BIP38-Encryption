'use strict';

var Bip32Encryption = require('../');
var chai = require('chai');
var assert = require('assert');
var should = chai.should();
var expect = chai.expect;

var fixtures = require('./fixtures');

describe('BIP32 encryption', function() {

  var bip32e;
  beforeEach(function() {
    bip32e = new Bip32Encryption();
  });

  describe('makeWallet', function() {

    fixtures.valid.forEach(function(f) {

      it('should make the clear text wallet for root key ' + f.rootKey, function() {
        var wallet = bip32e.makeWallet(f.rootKey, f.date);
        assert.equal(wallet, f.clear);
      });
    });

    fixtures.invalid.makeWallet.forEach(function(f) {
      it('should throw ' + f.description, function() {
        assert.throws(function() {
          bip32e.makeWallet(f.rootKey, f.creationDate, f.password, "", 0, f.saltEntrpy);
        }, new RegExp(f.exception));
      });
    });
  });

  describe('decryptWallet', function() {
    fixtures.valid.forEach(function(f) {

      it('should deserialize unencrypted wallet ' + f.clear, function() {
        var wallet = bip32e.decryptWallet(f.clear);
        assert.equal(wallet.rootKey, f.rootKey);
        assert.equal(wallet.date, f.date);
      });
    });

    fixtures.invalid.decryptWallet.forEach(function(f) {
      it('should throw ' + f.description, function() {
        assert.throws(function() {
          bip32e.decryptWallet(f.clear);
        }, new RegExp(f.exception));
      });
    });

  });
});
