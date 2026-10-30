// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const E = require('./lib/estate');
const { verify } = require('./lib/verify');
const F = require('./lib/format');

module.exports = {
  generateKey: E.generateKey,
  publicKey: E.publicKey,
  keyId: E.keyId,
  describeKey: E.describeKey,
  titleRef: E.titleRef,
  register: E.register,
  transfer: E.transfer,
  charge: E.charge,
  discharge: E.discharge,
  anchor: E.anchor,
  complete: E.complete,
  verify,
  anchorDigest: (envelope) => F.anchorDigest(F.parse(envelope)).toString('hex'),
  recordRef: (envelope) => F.refOf(F.parse(envelope)),
  FORMAT: F.FORMAT,
  ALGORITHM: F.ALGORITHM,
  KIND: F.KIND,
  TYPES: F.TYPES,
  TENURES: F.TENURES,
  PUBLIC_KEY_BYTES: F.PUBLIC_KEY_BYTES,
  SIGNATURE_BYTES: F.SIGNATURE_BYTES,
};
