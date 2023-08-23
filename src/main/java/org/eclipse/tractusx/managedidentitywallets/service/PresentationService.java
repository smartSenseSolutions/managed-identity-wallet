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

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.SignedJWT;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.text.StringEscapeUtils;
import org.eclipse.tractusx.managedidentitywallets.config.MIWSettings;
import org.eclipse.tractusx.managedidentitywallets.constant.StringPool;
import org.eclipse.tractusx.managedidentitywallets.dao.entity.Wallet;
import org.eclipse.tractusx.managedidentitywallets.exception.BadDataException;
import org.eclipse.tractusx.managedidentitywallets.exception.CredentialValidationProblem;
import org.eclipse.tractusx.managedidentitywallets.utils.Validate;
import org.eclipse.tractusx.ssi.lib.crypt.ed25519.Ed25519Key;
import org.eclipse.tractusx.ssi.lib.crypt.octet.OctetKeyPairFactory;
import org.eclipse.tractusx.ssi.lib.crypt.x21559.x21559PrivateKey;
import org.eclipse.tractusx.ssi.lib.did.resolver.DidDocumentResolverRegistry;
import org.eclipse.tractusx.ssi.lib.did.resolver.DidDocumentResolverRegistryImpl;
import org.eclipse.tractusx.ssi.lib.did.web.DidWebDocumentResolver;
import org.eclipse.tractusx.ssi.lib.did.web.util.DidWebParser;
import org.eclipse.tractusx.ssi.lib.exception.InvalidePrivateKeyFormat;
import org.eclipse.tractusx.ssi.lib.jwt.SignedJwtFactory;
import org.eclipse.tractusx.ssi.lib.jwt.SignedJwtValidator;
import org.eclipse.tractusx.ssi.lib.jwt.SignedJwtVerifier;
import org.eclipse.tractusx.ssi.lib.model.did.Did;
import org.eclipse.tractusx.ssi.lib.model.did.DidParser;
import org.eclipse.tractusx.ssi.lib.model.verifiable.credential.VerifiableCredential;
import org.eclipse.tractusx.ssi.lib.model.verifiable.presentation.VerifiablePresentation;
import org.eclipse.tractusx.ssi.lib.model.verifiable.presentation.VerifiablePresentationBuilder;
import org.eclipse.tractusx.ssi.lib.model.verifiable.presentation.VerifiablePresentationType;
import org.eclipse.tractusx.ssi.lib.serialization.jsonLd.JsonLdSerializerImpl;
import org.eclipse.tractusx.ssi.lib.serialization.jwt.SerializedJwtPresentationFactory;
import org.eclipse.tractusx.ssi.lib.serialization.jwt.SerializedJwtPresentationFactoryImpl;
import org.eclipse.tractusx.ssi.lib.serialization.jwt.SerializedVerifiablePresentation;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.net.URI;
import java.net.http.HttpClient;
import java.util.*;

/**
 * The type Presentation service.
 */
@Service
@Slf4j
@RequiredArgsConstructor
public class PresentationService {

    private final CommonService commonService;

    private final WalletKeyService walletKeyService;

    private final MIWSettings miwSettings;

    private final ObjectMapper objectMapper;

    private final CredentialService credentialService;


    /**
     * Create presentation map.
     *
     * @param data                     the data
     * @param withCredentialExpiryDate the with credential expiry date
     * @param withCredentialRevocation the with credential revocation
     * @param asJwt                    the as jwt
     * @param audience                 the audience
     * @param callerBpn                the caller bpn
     * @return the map
     */
    @SneakyThrows({InvalidePrivateKeyFormat.class})
    public Map<String, Object> createPresentation(Map<String, Object> data, boolean withCredentialExpiryDate, boolean withCredentialRevocation, boolean asJwt, String audience, String callerBpn) {
        List<Map<String, Object>> verifiableCredentialList = (List<Map<String, Object>>) data.get(StringPool.VERIFIABLE_CREDENTIALS);

        //check if holder wallet is in the system
        Wallet callerWallet = commonService.getWalletByIdentifier(callerBpn);

        List<VerifiableCredential> verifiableCredentials = new ArrayList<>(verifiableCredentialList.size());
        verifiableCredentialList.forEach(map -> {
            VerifiableCredential verifiableCredential = new VerifiableCredential(map);
            verifiableCredentials.add(verifiableCredential);
        });

        //validate all VCs
        validateCredentials(withCredentialExpiryDate, withCredentialRevocation, verifiableCredentials);

        Map<String, Object> response = new HashMap<>();
        if (asJwt) {
            log.debug("Creating VP as JWT for bpn ->{}", callerBpn);
            Validate.isFalse(StringUtils.hasText(audience)).launch(new BadDataException("Audience needed to create VP as JWT"));

            //Issuer of VP is holder of VC
            Did vpIssuerDid = DidParser.parse(callerWallet.getDid());

            //JWT Factory
            SerializedJwtPresentationFactory presentationFactory = new SerializedJwtPresentationFactoryImpl(
                    new SignedJwtFactory(new OctetKeyPairFactory()), new JsonLdSerializerImpl(), vpIssuerDid);

            //Build JWT
            Ed25519Key ed25519Key = walletKeyService.getPrivateKeyByWalletIdentifier(callerWallet.getId());
            x21559PrivateKey privateKey = new x21559PrivateKey(ed25519Key.getEncoded());
            SignedJWT presentation = presentationFactory.createPresentation(vpIssuerDid
                    , verifiableCredentials, audience, privateKey);

            response.put(StringPool.VP, presentation.serialize());
        } else {
            log.debug("Creating VP as JSON-LD for bpn ->{}", callerBpn);
            VerifiablePresentationBuilder verifiablePresentationBuilder =
                    new VerifiablePresentationBuilder();

            // Build VP
            VerifiablePresentation verifiablePresentation =
                    verifiablePresentationBuilder
                            .id(URI.create(miwSettings.authorityWalletDid() + "#" + UUID.randomUUID().toString()))
                            .type(List.of(VerifiablePresentationType.VERIFIABLE_PRESENTATION))
                            .verifiableCredentials(verifiableCredentials)
                            .build();
            response.put(StringPool.VP, verifiablePresentation);
        }
        return response;
    }

    /**
     * Validate presentation map.
     *
     * @param vp                       the vp
     * @param asJwt                    the as jwt
     * @param withCredentialExpiryDate the with credential expiry date
     * @param withCredentialRevocation the with credential revocation
     * @param audience                 the audience
     * @return the map
     */
    @SneakyThrows
    public Map<String, Object> validatePresentation(Map<String, Object> vp, boolean asJwt, boolean withCredentialExpiryDate, boolean withCredentialRevocation, String audience) {

        Map<String, Object> response = new HashMap<>();
        if (asJwt) {
            log.debug("Validating VP as JWT");
            //verify as jwt
            Validate.isNull(vp.get(StringPool.VP)).launch(new BadDataException("Can not find JWT"));
            String jwt = vp.get(StringPool.VP).toString();
            response.put(StringPool.VP, jwt);

            SignedJWT signedJWT = SignedJWT.parse(jwt);

            //validate VCs
            Map<String, Object> claims = objectMapper.readValue(signedJWT.getPayload().toBytes(), Map.class);
            String vpClaim = objectMapper.writeValueAsString(claims.get("vp"));
            JsonLdSerializerImpl jsonLdSerializer = new JsonLdSerializerImpl();
            VerifiablePresentation presentation = jsonLdSerializer.deserializePresentation(new SerializedVerifiablePresentation(vpClaim));
            List<VerifiableCredential> verifiableCredentials = presentation.getVerifiableCredentials();

            //validate VC
            validateCredentials(withCredentialExpiryDate, withCredentialRevocation, verifiableCredentials);

            //validate JWT sig.
            boolean validateSignature = validateSignature(signedJWT);

            //validate audience
            boolean validateAudience = validateAudience(audience, signedJWT);

            //validate jwt date
            boolean validateJWTExpiryDate = validateJWTExpiryDate(signedJWT);
            response.put(StringPool.VALIDATE_JWT_EXPIRY_DATE, validateJWTExpiryDate);

            response.put(StringPool.VALID, (validateSignature && validateAudience && validateJWTExpiryDate));

            if (StringUtils.hasText(audience)) {
                response.put(StringPool.VALIDATE_AUDIENCE, validateAudience);
            }

        } else {
            log.debug("Validating VP as json-ld");
            throw new BadDataException("Validation of VP in form of JSON-LD is not supported");
        }

        return response;
    }

    private boolean validateSignature(SignedJWT signedJWT) {
        //validate jwt signature
        try {
            DidDocumentResolverRegistry didDocumentResolverRegistry = new DidDocumentResolverRegistryImpl();
            didDocumentResolverRegistry.register(
                    new DidWebDocumentResolver(HttpClient.newHttpClient(), new DidWebParser(), miwSettings.enforceHttps()));

            SignedJwtVerifier jwtVerifier = new SignedJwtVerifier(didDocumentResolverRegistry);
            return jwtVerifier.verify(signedJWT);
        } catch (Exception e) {
            log.error("Can not verify signature of jwt", e);
            return false;
        }
    }

    private boolean validateJWTExpiryDate(SignedJWT signedJWT) {
        try {
            SignedJwtValidator jwtValidator = new SignedJwtValidator();
            jwtValidator.validateDate(signedJWT);
            return true;
        } catch (Exception e) {
            log.error("Can not expiry date ", e);
            return false;
        }
    }

    private boolean validateAudience(String audience, SignedJWT signedJWT) {
        if (StringUtils.hasText(audience)) {
            try {
                SignedJwtValidator jwtValidator = new SignedJwtValidator();
                jwtValidator.validateAudiences(signedJWT, audience);
                return true;
            } catch (Exception e) {
                log.error("Can not validate audience ", e);
                return false;
            }
        } else {
            return true;
        }
    }


    private void validateCredentials(boolean withCredentialExpiryDate, boolean withCredentialRevocation, List<VerifiableCredential> verifiableCredentials) {
        //validate VCs
        List<Map<String, Object>> validationResults = new ArrayList<>();
        verifiableCredentials.parallelStream().forEach(vc -> {
            Map<String, Object> map = credentialService.credentialsValidation(vc, withCredentialExpiryDate, withCredentialRevocation);
            if (!Boolean.parseBoolean(map.get(StringPool.VALID).toString())) {
                log.info("Invalid VC with ID - {}, validation response - {}", StringEscapeUtils.escapeJava(vc.getId().toString()), map);
            }
            map.put(StringPool.VC_ID, vc.getId().toString());
            map.remove(StringPool.VC);
            validationResults.add(map);
        });

        //check valid status of each VC, throw error if any one is invalid with details
        validationResults.forEach(result -> Validate.isFalse(Boolean.parseBoolean(result.get(StringPool.VALID).toString())).launch(new CredentialValidationProblem(validationResults, "One or more VCs are invalid")));
    }
}
