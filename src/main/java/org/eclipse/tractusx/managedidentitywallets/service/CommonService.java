/*
 * *******************************************************************************
 *  Copyright (c) 2021,2023 Contributors to the Eclipse Foundation
 *
 *  See the NOTICE file(s) distributed with this work for additional
 *  information regarding copyright ownership.
 *
 *  This program and the accompanying materials are made available under the
 *  terms of the Apache License, Version 2.0 which is available at
 *  https://www.apache.org/licenses/LICENSE-2.0.
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 *  License for the specific language governing permissions and limitations
 *  under the License.
 *
 *  SPDX-License-Identifier: Apache-2.0
 * ******************************************************************************
 */

package org.eclipse.tractusx.managedidentitywallets.service;

import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.text.StringEscapeUtils;
import org.eclipse.tractusx.managedidentitywallets.config.RevocationSettings;
import org.eclipse.tractusx.managedidentitywallets.constant.StringPool;
import org.eclipse.tractusx.managedidentitywallets.dao.entity.HoldersCredential;
import org.eclipse.tractusx.managedidentitywallets.dao.entity.Wallet;
import org.eclipse.tractusx.managedidentitywallets.dao.repository.WalletRepository;
import org.eclipse.tractusx.managedidentitywallets.exception.WalletNotFoundProblem;
import org.eclipse.tractusx.managedidentitywallets.revocation.service.RevocationService;
import org.eclipse.tractusx.managedidentitywallets.utils.CommonUtils;
import org.eclipse.tractusx.managedidentitywallets.utils.Validate;
import org.eclipse.tractusx.ssi.lib.crypt.x21559.x21559PrivateKey;
import org.eclipse.tractusx.ssi.lib.exception.DidParseException;
import org.eclipse.tractusx.ssi.lib.exception.InvalidePrivateKeyFormat;
import org.eclipse.tractusx.ssi.lib.exception.UnsupportedSignatureTypeException;
import org.eclipse.tractusx.ssi.lib.model.did.DidDocument;
import org.eclipse.tractusx.ssi.lib.model.proof.jws.JWSSignature2020;
import org.eclipse.tractusx.ssi.lib.model.verifiable.credential.VerifiableCredential;
import org.eclipse.tractusx.ssi.lib.model.verifiable.credential.VerifiableCredentialBuilder;
import org.eclipse.tractusx.ssi.lib.model.verifiable.credential.VerifiableCredentialSubject;
import org.eclipse.tractusx.ssi.lib.model.verifiable.credential.VerifiableCredentialType;
import org.eclipse.tractusx.ssi.lib.proof.LinkedDataProofGenerator;
import org.eclipse.tractusx.ssi.lib.proof.SignatureType;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.time.Instant;
import java.util.*;

/**
 * The type Common service.
 */
@Service
@Slf4j
@RequiredArgsConstructor
public class CommonService {

    private final WalletRepository walletRepository;

    private final RevocationService revocationService;

    private final RevocationSettings revocationSettings;

    /**
     * Gets wallet by identifier(BPN or did).
     *
     * @param identifier the identifier
     * @return the wallet by identifier
     */
    public Wallet getWalletByIdentifier(String identifier) {
        Wallet wallet;
        if (CommonUtils.getIdentifierType(identifier).equals(StringPool.BPN)) {
            wallet = walletRepository.getByBpn(identifier);
        } else {
            try {
                wallet = walletRepository.getByDid(identifier);
            } catch (DidParseException e) {
                log.error("Error while parsing did {}", StringEscapeUtils.escapeJava(identifier), e);
                throw new WalletNotFoundProblem("Error while parsing did " + identifier);
            }
        }
        Validate.isNull(wallet).launch(new WalletNotFoundProblem("Wallet not found for identifier " + identifier));
        return wallet;
    }

    /**
     * Validate expiry boolean.
     *
     * @param withCredentialExpiryDate the with credential expiry date
     * @param verifiableCredential     the verifiable credential
     * @param response                 the response
     * @return the boolean
     */
    public static boolean validateExpiry(boolean withCredentialExpiryDate, VerifiableCredential verifiableCredential, Map<String, Object> response) {
        //validate expiry date
        boolean dateValidation = true;
        if (withCredentialExpiryDate) {
            Instant expirationDate = verifiableCredential.getExpirationDate();
            if (expirationDate.isBefore(Instant.now())) {
                dateValidation = false;
                response.put(StringPool.VALIDATE_EXPIRY_DATE, false);
            } else {
                response.put(StringPool.VALIDATE_EXPIRY_DATE, true);
            }
        }
        return dateValidation;
    }

    /**
     * Gets holders credential.
     *
     * @param vc                    the vc
     * @param issuerDidDocument     the issuer did document
     * @param issuerPrivateKeyBytes the issuer private key bytes
     * @param holderDid             the holder did
     * @param selfIssued            the self issued
     * @return the holders credential
     */
    public HoldersCredential getHoldersCredential(VerifiableCredential vc, DidDocument issuerDidDocument, byte[] issuerPrivateKeyBytes, String holderDid, boolean selfIssued) {
        return getHoldersCredential(vc, issuerDidDocument, issuerPrivateKeyBytes, holderDid, selfIssued, false);
    }

    /**
     * Gets holders credential.
     *
     * @param vc                    the vc
     * @param issuerDidDocument     the issuer did document
     * @param issuerPrivateKeyBytes the issuer private key bytes
     * @param holderDid             the holder did
     * @param selfIssued            the self issued
     * @param revocable             the revocable
     * @return the holders credential
     */
    public HoldersCredential getHoldersCredential(VerifiableCredential vc, DidDocument issuerDidDocument, byte[] issuerPrivateKeyBytes, String holderDid, boolean selfIssued, boolean revocable) {
        List<String> cloneTypes = new ArrayList<>(vc.getTypes());

        // Create VC
        VerifiableCredential verifiableCredential = createVerifiableCredential(vc, issuerDidDocument, issuerPrivateKeyBytes, revocable);

        cloneTypes.remove(VerifiableCredentialType.VERIFIABLE_CREDENTIAL);

        // Create Credential
        return HoldersCredential.builder()
                .holderDid(holderDid)
                .issuerDid(issuerDidDocument.getId().toString())
                .type(String.join(",", cloneTypes))
                .credentialId(verifiableCredential.getId().toString())
                .data(verifiableCredential)
                .selfIssued(selfIssued)
                .build();
    }

    @SneakyThrows({UnsupportedSignatureTypeException.class, InvalidePrivateKeyFormat.class})
    private VerifiableCredential createVerifiableCredential(VerifiableCredential verifiableCredential, DidDocument issuerDidDocument, byte[] issuerPrivateKey, boolean revocable) {
        //VC Builder
        List<URI> contexts = verifiableCredential.getContext();
        VerifiableCredentialSubject verifiableCredentialSubject = verifiableCredential.getCredentialSubject().get(0);

        Instant expiryDate = null;
        if (!Objects.isNull(verifiableCredential.getExpirationDate())) {
            expiryDate = Date.from(verifiableCredential.getExpirationDate()).toInstant();
        }

        // if the credential does not contain the JWS proof-context add it
        URI jwsUri = URI.create("https://w3id.org/security/suites/jws-2020/v1");
        if (!contexts.contains(jwsUri)) {
            contexts.add(jwsUri);
        }

        VerifiableCredentialBuilder builder =
                new VerifiableCredentialBuilder()
                        .id(verifiableCredential.getId())
                        .type(verifiableCredential.getTypes())
                        .issuer(verifiableCredential.getIssuer())
                        .expirationDate(expiryDate)
                        .issuanceDate(Instant.now())
                        .credentialSubject(verifiableCredentialSubject);

        //if VC is revocable
        if (revocable) {
            builder.verifiableCredentialStatus(revocationService.statusEntryForSuspension(issuerDidDocument.getId().toString()));
            //add revocation context
            contexts.add(revocationSettings.contextUrl());
        }

        builder.context(contexts);

        LinkedDataProofGenerator generator = LinkedDataProofGenerator.newInstance(SignatureType.JWS);
        URI verificationMethod = issuerDidDocument.getVerificationMethods().get(0).getId();

        JWSSignature2020 proof =
                (JWSSignature2020) generator.createProof(builder.build(), verificationMethod, new x21559PrivateKey(issuerPrivateKey));


        //Adding Proof to VC
        builder.proof(proof);

        //Create Credential
        return builder.build();
    }

}
