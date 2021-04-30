/*
 * Copyright 2021 Paul Schaub.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.pgpainless.signature;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.algorithm.SignatureType;
import org.pgpainless.exception.SignatureValidationException;
import org.pgpainless.policy.Policy;
import org.pgpainless.signature.subpackets.SignatureSubpacketsUtil;

public class SignatureChainValidator {

    private static final Logger LOGGER = Logger.getLogger(SignatureChainValidator.class.getName());

    public static boolean validateSigningKey(PGPSignature signature, PGPPublicKeyRing signingKeyRing, Policy policy, Date validationDate) throws SignatureValidationException {

        Map<PGPSignature, Exception> rejections = new ConcurrentHashMap<>();

        PGPPublicKey signingSubkey = signingKeyRing.getPublicKey(signature.getKeyID());
        if (signingSubkey == null) {
            throw new SignatureValidationException("Provided key ring does not contain a subkey with id " + Long.toHexString(signature.getKeyID()));
        }

        PGPPublicKey primaryKey = signingKeyRing.getPublicKey();

        List<PGPSignature> directKeySignatures = new ArrayList<>();
        Iterator<PGPSignature> primaryKeyRevocationIterator = primaryKey.getSignaturesOfType(SignatureType.KEY_REVOCATION.getCode());
        while (primaryKeyRevocationIterator.hasNext()) {
            PGPSignature revocation = primaryKeyRevocationIterator.next();
            try {
                if (SignatureValidator.verifyKeyRevocationSignature(revocation, primaryKey, policy, signature.getCreationTime())) {
                    directKeySignatures.add(revocation);
                }
            } catch (SignatureValidationException e) {
                rejections.put(revocation, e);
                LOGGER.log(Level.FINE, "Rejecting key revocation signature.", e);
            }
        }

        Iterator<PGPSignature> keySignatures = primaryKey.getSignaturesOfType(SignatureType.DIRECT_KEY.getCode());
        while (keySignatures.hasNext()) {
            PGPSignature keySignature = keySignatures.next();
            try {
                if (SignatureValidator.verifyDirectKeySignature(keySignature, primaryKey, policy, signature.getCreationTime())) {
                    directKeySignatures.add(keySignature);
                }
            } catch (SignatureValidationException e) {
                rejections.put(keySignature, e);
                LOGGER.log(Level.FINE, "Rejecting key signature.", e);
            }
        }

        Collections.sort(directKeySignatures, new SignatureValidityComparator(SignatureCreationDateComparator.Order.NEW_TO_OLD));
        if (directKeySignatures.isEmpty()) {

        } else {
            if (directKeySignatures.get(0).getSignatureType() == SignatureType.KEY_REVOCATION.getCode()) {
                throw new SignatureValidationException("Primary key has been revoked.");
            }
        }

        Iterator<String> userIds = primaryKey.getUserIDs();
        Map<String, List<PGPSignature>> userIdSignatures = new ConcurrentHashMap<>();
        while (userIds.hasNext()) {
            List<PGPSignature> signaturesOnUserId = new ArrayList<>();
            String userId = userIds.next();
            Iterator<PGPSignature> userIdSigs = primaryKey.getSignaturesForID(userId);
            while (userIdSigs.hasNext()) {
                PGPSignature userIdSig = userIdSigs.next();
                try {
                    if (SignatureValidator.verifySignatureOverUserId(userId, userIdSig, primaryKey, policy, signature.getCreationTime())) {
                        signaturesOnUserId.add(userIdSig);
                    }
                } catch (SignatureValidationException e) {
                    rejections.put(userIdSig, e);
                    LOGGER.log(Level.INFO, "Rejecting user-id signature.", e);
                }
            }
            Collections.sort(signaturesOnUserId, new SignatureValidityComparator(SignatureCreationDateComparator.Order.NEW_TO_OLD));
            userIdSignatures.put(userId, signaturesOnUserId);
        }

        boolean userIdValid = false;
        for (String userId : userIdSignatures.keySet()) {
            if (!userIdSignatures.get(userId).isEmpty()) {
                PGPSignature current = userIdSignatures.get(userId).get(0);
                if (current.getSignatureType() == SignatureType.CERTIFICATION_REVOCATION.getCode()) {
                    LOGGER.log(Level.FINE, "User-ID '" + userId + "' is revoked.");
                } else {
                    userIdValid = true;
                }
            }
        }

        if (!userIdValid) {
            throw new SignatureValidationException("Key is not valid at this point.", rejections);
        }

        if (signingSubkey != primaryKey) {
            List<PGPSignature> subkeySigs = new ArrayList<>();
            Iterator<PGPSignature> bindingRevocations = signingSubkey.getSignaturesOfType(SignatureType.SUBKEY_REVOCATION.getCode());
            while (bindingRevocations.hasNext()) {
                PGPSignature revocation = bindingRevocations.next();
                try {
                    if (SignatureValidator.verifySubkeyBindingRevocation(revocation, primaryKey, signingSubkey, policy, signature.getCreationTime())) {
                        subkeySigs.add(revocation);
                    }
                } catch (SignatureValidationException e) {
                    rejections.put(revocation, e);
                    LOGGER.log(Level.FINE, "Rejecting subkey revocation signature.", e);
                }
            }

            Iterator<PGPSignature> bindingSigs = signingSubkey.getSignaturesOfType(SignatureType.SUBKEY_BINDING.getCode());
            while (bindingSigs.hasNext()) {
                PGPSignature bindingSig = bindingSigs.next();
                try {
                    if (SignatureValidator.verifySubkeyBindingSignature(bindingSig, primaryKey, signingSubkey, policy, signature.getCreationTime())) {
                        subkeySigs.add(bindingSig);
                    }
                } catch (SignatureValidationException e) {
                    rejections.put(bindingSig, e);
                    LOGGER.log(Level.FINE, "Rejecting subkey binding signature.", e);
                }
            }

            Collections.sort(subkeySigs, new SignatureValidityComparator(SignatureCreationDateComparator.Order.NEW_TO_OLD));
            if (subkeySigs.isEmpty()) {
                throw new SignatureValidationException("Subkey is not bound.", rejections);
            }

            PGPSignature currentSig = subkeySigs.get(0);
            if (currentSig.getSignatureType() == SignatureType.SUBKEY_REVOCATION.getCode()) {
                throw new SignatureValidationException("Subkey is revoked.");
            }

            if (!KeyFlag.hasKeyFlag(SignatureSubpacketsUtil.getKeyFlags(currentSig).getFlags(), KeyFlag.SIGN_DATA)) {
                throw new SignatureValidationException("Signature was made by key which is not capable of signing.");
            }
        }
        return true;
    }

    public static boolean validateSignatureChain(PGPSignature signature, InputStream signedData, PGPPublicKeyRing signingKeyRing, Policy policy, Date validationDate)
            throws SignatureValidationException {
        validateSigningKey(signature, signingKeyRing, policy, validationDate);
        return SignatureValidator.verifyUninitializedSignature(signature, signedData, signingKeyRing.getPublicKey(signature.getKeyID()), policy, validationDate);
    }

    public static boolean validateSignature(PGPSignature signature, PGPPublicKeyRing verificationKeys, Policy policy) throws SignatureValidationException {
        validateSigningKey(signature, verificationKeys, policy, signature.getCreationTime());
        PGPPublicKey signingKey = verificationKeys.getPublicKey(signature.getKeyID());
        SignatureValidator.verifyInitializedSignature(signature, signingKey, policy, signature.getCreationTime());
        return true;
    }
}
