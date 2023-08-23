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

package org.eclipse.tractusx.managedidentitywallets.vp;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.teketik.test.mockinbean.MockInBean;
import lombok.extern.slf4j.Slf4j;
import org.eclipse.tractusx.managedidentitywallets.ManagedIdentityWalletsApplication;
import org.eclipse.tractusx.managedidentitywallets.config.MIWSettings;
import org.eclipse.tractusx.managedidentitywallets.config.RevocationSettings;
import org.eclipse.tractusx.managedidentitywallets.config.TestContextInitializer;
import org.eclipse.tractusx.managedidentitywallets.constant.MIWVerifiableCredentialType;
import org.eclipse.tractusx.managedidentitywallets.constant.RestURI;
import org.eclipse.tractusx.managedidentitywallets.constant.StringPool;
import org.eclipse.tractusx.managedidentitywallets.controller.PresentationController;
import org.eclipse.tractusx.managedidentitywallets.dao.entity.HoldersCredential;
import org.eclipse.tractusx.managedidentitywallets.dao.entity.Wallet;
import org.eclipse.tractusx.managedidentitywallets.dao.repository.HoldersCredentialRepository;
import org.eclipse.tractusx.managedidentitywallets.exception.CredentialValidationProblem;
import org.eclipse.tractusx.managedidentitywallets.revocation.client.RevocationClient;
import org.eclipse.tractusx.managedidentitywallets.revocation.model.StatusVerificationRequest;
import org.eclipse.tractusx.managedidentitywallets.revocation.model.StatusVerificationResponse;
import org.eclipse.tractusx.managedidentitywallets.revocation.service.RevocationService;
import org.eclipse.tractusx.managedidentitywallets.service.PresentationService;
import org.eclipse.tractusx.managedidentitywallets.utils.AuthenticationUtils;
import org.eclipse.tractusx.managedidentitywallets.utils.TestUtils;
import org.eclipse.tractusx.ssi.lib.did.resolver.DidDocumentResolverRegistry;
import org.eclipse.tractusx.ssi.lib.did.resolver.DidDocumentResolverRegistryImpl;
import org.eclipse.tractusx.ssi.lib.did.web.DidWebFactory;
import org.eclipse.tractusx.ssi.lib.exception.DidDocumentResolverNotRegisteredException;
import org.eclipse.tractusx.ssi.lib.exception.JwtException;
import org.eclipse.tractusx.ssi.lib.jwt.SignedJwtVerifier;
import org.eclipse.tractusx.ssi.lib.model.verifiable.credential.VerifiableCredential;
import org.eclipse.tractusx.ssi.lib.model.verifiable.credential.VerifiableCredentialType;
import org.eclipse.tractusx.ssi.lib.proof.LinkedDataProofValidation;
import org.eclipse.tractusx.ssi.lib.proof.SignatureType;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.MockedConstruction;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.*;
import org.springframework.test.context.ContextConfiguration;

import java.text.ParseException;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.DEFINED_PORT, classes = {ManagedIdentityWalletsApplication.class})
@ContextConfiguration(initializers = {TestContextInitializer.class})
@Slf4j
class PresentationTest {

    @Autowired
    private TestRestTemplate restTemplate;

    @Autowired
    private HoldersCredentialRepository holdersCredentialRepository;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private PresentationController presentationController;

    @Autowired
    private MIWSettings miwSettings;

    @Autowired
    private PresentationService presentationService;

    @MockInBean(RevocationService.class)
    private RevocationClient revocationClient;

    @Autowired
    private RevocationSettings revocationSettings;

    @Test
    void validateVPAssJsonLd400() throws JsonProcessingException {
        //create VP
        String bpn = UUID.randomUUID().toString();
        String audience = "companyA";
        ResponseEntity<Map> vpResponse = createBpnVCAsJwt(bpn, audience);
        Map body = vpResponse.getBody();

        //validate VP
        HttpHeaders headers = AuthenticationUtils.getValidUserHttpHeaders(bpn);
        HttpEntity<Map> entity = new HttpEntity<>(body, headers);

        ResponseEntity<Map> validationResponse = restTemplate.exchange(RestURI.API_PRESENTATIONS_VALIDATION, HttpMethod.POST, entity, Map.class);
        Assertions.assertEquals(validationResponse.getStatusCode().value(), HttpStatus.BAD_REQUEST.value());
    }

    @Test
    @DisplayName("validate VP with expired JWT")
    void validateVPWithExpiredJWT() throws JsonProcessingException, InterruptedException, DidDocumentResolverNotRegisteredException, JwtException {
        String bpn = UUID.randomUUID().toString();
        String audience = "companyA";

        Map<String, Object> presentation = createVP(bpn, audience, true);
        Assertions.assertNotNull(presentation);
        Map<String, Object> vpResponse = presentation;
        try (MockedConstruction<SignedJwtVerifier> mocked = Mockito.mockConstruction(SignedJwtVerifier.class)) {

            DidDocumentResolverRegistry didDocumentResolverRegistry = Mockito.mock(DidDocumentResolverRegistry.class);
            SignedJwtVerifier signedJwtVerifier = new SignedJwtVerifier(didDocumentResolverRegistry);

            Mockito.doThrow(new JwtException("invalid")).when(signedJwtVerifier).verify(Mockito.any(SignedJWT.class));
            log.info("Waiting for 62 sec.");
            Thread.sleep(62000L); // need to remove this??? Can not mock 2 object creation using new
            try (MockedStatic<LinkedDataProofValidation> utils = Mockito.mockStatic(LinkedDataProofValidation.class)) {
                //mock VC verification
                //mock setup
                mockVCSignatureVarification(utils, true);

                ///mock revocation
                mockRevocationVerification(true);

                Assertions.assertDoesNotThrow(() -> {
                    ResponseEntity<Map<String, Object>> response = presentationController.validatePresentation(vpResponse, "invalid Audience", true, false, false);
                    Assertions.assertEquals(response.getStatusCode().value(), HttpStatus.OK.value());
                    Assertions.assertFalse(Boolean.parseBoolean(response.getBody().get(StringPool.VALID).toString()));
                    Assertions.assertFalse(Boolean.parseBoolean(response.getBody().get(StringPool.VALIDATE_JWT_EXPIRY_DATE).toString()));
                    Assertions.assertFalse(Boolean.parseBoolean(response.getBody().get(StringPool.VALIDATE_AUDIENCE).toString()));
                });
                Mockito.reset(revocationClient);
            }
        }

    }

    @Test
    @DisplayName("Validate VP which is created with invalid VC signature, it should give 400")
    void validateVpWithInvalidVCSignature() throws JsonProcessingException {
        //create VP
        String bpn = UUID.randomUUID().toString();
        String audience = "companyA";

        Map<String, Object> presentation = createVP(bpn, audience, true);

        Assertions.assertNotNull(presentation);
        Map<String, Object> vpResponse = presentation;
        try (MockedStatic<LinkedDataProofValidation> utils = Mockito.mockStatic(LinkedDataProofValidation.class)) {
            //mock VC verification
            //mock setup
            mockVCSignatureVarification(utils, false);

            ///mock revocation
            mockRevocationVerification(false);

            Assertions.assertThrows(CredentialValidationProblem.class, () -> {
                try {
                    presentationController.validatePresentation(vpResponse, audience, true, false, false);
                } catch (CredentialValidationProblem v) {
                    List<Map<String, Object>> validationResults = v.getValidationResults();
                    Assertions.assertFalse(Boolean.parseBoolean(validationResults.get(0).get(StringPool.VALID).toString()));
                    throw v;
                }
            });
            Mockito.reset(revocationClient);
        }
    }

    @Test
    @DisplayName("Validate VP(created with expired and revoked VC) as JWT with invalid audience, verify VC expiry = false and verify VC revocation = false, it should give valid=false")
    void validateVpWithInvalidAudienceWithoutVerifyVC() throws JsonProcessingException {
        String bpn = UUID.randomUUID().toString();
        String audience = "companyA";

        Map<String, Object> presentation = createVP(bpn, audience, true);
        Assertions.assertNotNull(presentation);
        Map<String, Object> vpResponse = presentation;

        try (MockedStatic<LinkedDataProofValidation> utils = Mockito.mockStatic(LinkedDataProofValidation.class)) {
            //mock VC verification
            //mock setup
            mockVCSignatureVarification(utils, true);

            ///mock revocation
            mockRevocationVerification(true);

            Assertions.assertDoesNotThrow(() -> {
                ResponseEntity<Map<String, Object>> response = presentationController.validatePresentation(vpResponse, "invalid Audience", true, false, false);
                Assertions.assertEquals(response.getStatusCode().value(), HttpStatus.OK.value());
                Assertions.assertFalse(Boolean.parseBoolean(response.getBody().get(StringPool.VALID).toString()));
                Assertions.assertTrue(Boolean.parseBoolean(response.getBody().get(StringPool.VALIDATE_JWT_EXPIRY_DATE).toString()));
                Assertions.assertFalse(Boolean.parseBoolean(response.getBody().get(StringPool.VALIDATE_AUDIENCE).toString()));
            });
            Mockito.reset(revocationClient);
        }
    }

    @Test
    @DisplayName("Validate VP(created with expired and revoked VC) as JWT with verify VC expiry = false and verify VC revocation = false, it should return 200")
    void validateVpWithoutVerifyVC() throws JsonProcessingException {
        //create VP
        String bpn = UUID.randomUUID().toString();
        String audience = "companyA";

        Map<String, Object> presentation = createVP(bpn, audience, true);
        Assertions.assertNotNull(presentation);
        Map<String, Object> vpResponse = presentation;

        try (MockedStatic<LinkedDataProofValidation> utils = Mockito.mockStatic(LinkedDataProofValidation.class)) {
            //mock VC verification
            //mock setup
            mockVCSignatureVarification(utils, true);

            ///mock revocation
            mockRevocationVerification(true);

            Assertions.assertDoesNotThrow(() -> {
                ResponseEntity<Map<String, Object>> response = presentationController.validatePresentation(vpResponse, audience, true, false, false);
                Assertions.assertEquals(response.getStatusCode().value(), HttpStatus.OK.value());
                Assertions.assertTrue(Boolean.parseBoolean(response.getBody().get(StringPool.VALID).toString()));
                Assertions.assertTrue(Boolean.parseBoolean(response.getBody().get(StringPool.VALIDATE_JWT_EXPIRY_DATE).toString()));
                Assertions.assertTrue(Boolean.parseBoolean(response.getBody().get(StringPool.VALIDATE_AUDIENCE).toString()));
            });
            Mockito.reset(revocationClient);
        }
    }

    @Test
    @DisplayName("Validate VP(created with expired and revoked VC) as JWT with verify VC expiry = true and verify VC revocation = true, it should be give error with 400")
    void validateVPWithVerifyVCExpiryAndRevocation() throws JsonProcessingException {
        //create VP
        String bpn = UUID.randomUUID().toString();
        String audience = "companyA";

        Map<String, Object> presentation = createVP(bpn, audience, true);

        Assertions.assertNotNull(presentation);
        Map<String, Object> vpResponse = presentation;
        try (MockedStatic<LinkedDataProofValidation> utils = Mockito.mockStatic(LinkedDataProofValidation.class)) {
            //mock VC verification
            //mock setup
            mockVCSignatureVarification(utils, true);

            ///mock revocation
            mockRevocationVerification(true);

            Assertions.assertThrows(CredentialValidationProblem.class, () -> {
                try {
                    presentationController.validatePresentation(vpResponse, audience, true, true, true);
                } catch (CredentialValidationProblem v) {
                    List<Map<String, Object>> validationResults = v.getValidationResults();
                    Assertions.assertFalse(Boolean.parseBoolean(validationResults.get(0).get(StringPool.VALID).toString()));
                    Assertions.assertFalse(Boolean.parseBoolean(validationResults.get(0).get(StringPool.VALIDATE_EXPIRY_DATE).toString()));
                    Assertions.assertTrue(Boolean.parseBoolean(validationResults.get(0).get(StringPool.REVOKED).toString()));
                    throw v;
                }
            });
            Mockito.reset(revocationClient);
        }
    }

    private Map<String, Object> createVP(String bpn, String audience, boolean expiredVC) throws JsonProcessingException {
        ResponseEntity<String> response = TestUtils.createWallet(bpn, bpn, restTemplate, miwSettings.authorityWalletBpn());
        Assertions.assertEquals(response.getStatusCode().value(), HttpStatus.CREATED.value());
        Wallet wallet = TestUtils.getWalletFromString(response.getBody());

        //issue VC
        VerifiableCredential credential = TestUtils.issueRandomVC(wallet.getDid(), miwSettings.authorityWalletDid(), miwSettings, objectMapper, revocationClient, restTemplate);

        if (expiredVC) {
            //modify expiry date
            Instant instant = Instant.now().minusSeconds(60);
            credential.put("expirationDate", instant.toString());
        }

        //create VP
        Map<String, Object> presentation = null;
        //create request
        Map<String, Object> request = new HashMap<>();
        request.put(StringPool.HOLDER_IDENTIFIER, wallet.getDid());
        request.put(StringPool.VERIFIABLE_CREDENTIALS, List.of(objectMapper.readValue(credential.toJson(), Map.class)));
        try (MockedStatic<LinkedDataProofValidation> utils = Mockito.mockStatic(LinkedDataProofValidation.class)) {
            //mock VC verification
            //mock setup
            mockVCSignatureVarification(utils, true);

            presentation = presentationService.createPresentation(request, false, false, true, audience, bpn);
        }
        return presentation;
    }

    @Test
    @DisplayName("Create VP as JWT of expired and revoked VC with revocation status check = true and check vc expiry check = true, it should give error with status 400")
    void createPresentationAsJWTWithExpiredAndRevokedVC400() throws JsonProcessingException {
        String bpn = UUID.randomUUID().toString();
        Wallet wallet = TestUtils.getWalletFromString(TestUtils.createWallet(bpn, bpn, restTemplate, miwSettings.authorityWalletBpn()).getBody());
        String audience = "audience";

        VerifiableCredential vc1 = TestUtils.issueRandomVC(wallet.getDid(), miwSettings.authorityWalletDid(), miwSettings, objectMapper, revocationClient, restTemplate);

        //modify expiry date
        Instant instant = Instant.now().minusSeconds(60);
        vc1.put("expirationDate", instant.toString());

        Map<String, Object> request = new HashMap<>();
        request.put(StringPool.HOLDER_IDENTIFIER, wallet.getDid());
        request.put(StringPool.VERIFIABLE_CREDENTIALS, List.of(objectMapper.readValue(vc1.toJson(), Map.class)));


        try (MockedStatic<LinkedDataProofValidation> utils = Mockito.mockStatic(LinkedDataProofValidation.class)) {
            //mock VC verification
            //mock setup
            mockVCSignatureVarification(utils, true);

            ///mock revocation
            mockRevocationVerification(true);


            Assertions.assertThrows(CredentialValidationProblem.class, () -> {
                try {
                    presentationService.createPresentation(request, true, true, true, audience, bpn);
                } catch (CredentialValidationProblem credentialValidationProblem) {
                    Assertions.assertFalse(Boolean.parseBoolean(credentialValidationProblem.getValidationResults().get(0).get(StringPool.VALID).toString()));
                    Assertions.assertFalse(Boolean.parseBoolean(credentialValidationProblem.getValidationResults().get(0).get(StringPool.VALIDATE_EXPIRY_DATE).toString()));
                    Assertions.assertTrue(Boolean.parseBoolean(credentialValidationProblem.getValidationResults().get(0).get(StringPool.REVOKED).toString()));
                    throw credentialValidationProblem;
                }
            });
        }
    }

    @Test
    @DisplayName("Create VP as JWT of expired VC and valid VC with revocation status check = false and check vc expiry check = true, it should give error with status 400")
    void createPresentationAsJWTWithExpiredVC400() throws JsonProcessingException {
        String bpn = UUID.randomUUID().toString();
        Wallet wallet = TestUtils.getWalletFromString(TestUtils.createWallet(bpn, bpn, restTemplate, miwSettings.authorityWalletBpn()).getBody());
        String audience = "audience";

        VerifiableCredential vc1 = TestUtils.issueRandomVC(wallet.getDid(), miwSettings.authorityWalletDid(), miwSettings, objectMapper, revocationClient, restTemplate);
        String invalidVcId = vc1.getId().toString();
        //modify expiry date
        Instant instant = Instant.now().minusSeconds(60);
        vc1.put("expirationDate", instant.toString());

        //valid VC
        VerifiableCredential vc2 = TestUtils.issueRandomVC(wallet.getDid(), miwSettings.authorityWalletDid(), miwSettings, objectMapper, revocationClient, restTemplate);

        Map<String, Object> request = new HashMap<>();
        request.put(StringPool.HOLDER_IDENTIFIER, wallet.getDid());
        request.put(StringPool.VERIFIABLE_CREDENTIALS, List.of(objectMapper.readValue(vc1.toJson(), Map.class), objectMapper.readValue(vc2.toJson(), Map.class)));
        HttpHeaders headers = AuthenticationUtils.getValidUserHttpHeaders(bpn);
        headers.put(HttpHeaders.CONTENT_TYPE, List.of(MediaType.APPLICATION_JSON_VALUE));
        HttpEntity<String> entity = new HttpEntity<>(objectMapper.writeValueAsString(request), headers);

        try (MockedStatic<LinkedDataProofValidation> utils = Mockito.mockStatic(LinkedDataProofValidation.class)) {
            //mock VC verification
            //mock setup
            mockVCSignatureVarification(utils, true);

            Assertions.assertThrows(CredentialValidationProblem.class, () -> {
                try {
                    presentationService.createPresentation(request, true, false, true, audience, bpn);
                } catch (CredentialValidationProblem credentialValidationProblem) {

                    List<Map<String, Object>> validationResults = credentialValidationProblem.getValidationResults();
                    validationResults.forEach(data -> {
                        String string = data.get(StringPool.VC_ID).toString();
                        if (string.equals(invalidVcId)) {
                            Assertions.assertFalse(Boolean.parseBoolean(data.get(StringPool.VALID).toString()));
                            Assertions.assertFalse(Boolean.parseBoolean(data.get(StringPool.VALIDATE_EXPIRY_DATE).toString()));
                        } else {
                            Assertions.assertTrue(Boolean.parseBoolean(data.get(StringPool.VALID).toString()));
                            Assertions.assertTrue(Boolean.parseBoolean(data.get(StringPool.VALIDATE_EXPIRY_DATE).toString()));
                        }
                    });
                    throw credentialValidationProblem;
                } catch (Exception e) {
                    System.out.println();
                }
            });
        }
    }

    @Test
    @DisplayName("Create VP as JWT of revoked VC with revocation status check = true and vc expiry check = false, it should give error with status 400")
    void createPresentationAsJWTWithRevokedVC400() throws JsonProcessingException {
        String bpn = UUID.randomUUID().toString();
        Wallet wallet = TestUtils.getWalletFromString(TestUtils.createWallet(bpn, bpn, restTemplate, miwSettings.authorityWalletBpn()).getBody());
        String audience = "audience";

        VerifiableCredential vc1 = TestUtils.issueRandomVC(wallet.getDid(), miwSettings.authorityWalletDid(), miwSettings, objectMapper, revocationClient, restTemplate);
        Map<String, Object> request = new HashMap<>();
        request.put(StringPool.HOLDER_IDENTIFIER, wallet.getDid());
        request.put(StringPool.VERIFIABLE_CREDENTIALS, List.of(objectMapper.readValue(vc1.toJson(), Map.class)));
        HttpHeaders headers = AuthenticationUtils.getValidUserHttpHeaders(bpn);
        headers.put(HttpHeaders.CONTENT_TYPE, List.of(MediaType.APPLICATION_JSON_VALUE));
        HttpEntity<String> entity = new HttpEntity<>(objectMapper.writeValueAsString(request), headers);
        try (MockedStatic<LinkedDataProofValidation> utils = Mockito.mockStatic(LinkedDataProofValidation.class)) {
            //mock VC verification
            //mock setup
            mockVCSignatureVarification(utils, true);
            ///mock revocation
            mockRevocationVerification(true);

            Assertions.assertThrows(CredentialValidationProblem.class, () -> {
                try {
                    presentationService.createPresentation(request, false, true, true, audience, bpn);
                } catch (CredentialValidationProblem credentialValidationProblem) {
                    List<Map<String, Object>> validationResults = credentialValidationProblem.getValidationResults();
                    Assertions.assertFalse(Boolean.parseBoolean(validationResults.get(0).get(StringPool.VALID).toString()));
                    Assertions.assertTrue(Boolean.parseBoolean(validationResults.get(0).get(StringPool.REVOKED).toString()));
                    throw credentialValidationProblem;
                }
            });
            Mockito.reset(revocationClient);
        }
    }

    @Test
    @DisplayName("Create VP as JWT from 5 valid VC and check VC expiry = true date and revocation status check = true. It should create VP with status 201")
    void createPresentationAsJWT201() throws JsonProcessingException, ParseException {
        String bpn = UUID.randomUUID().toString();
        Wallet wallet = TestUtils.getWalletFromString(TestUtils.createWallet(bpn, bpn, restTemplate, miwSettings.authorityWalletBpn()).getBody());
        String audience = "audience";
        String did = DidWebFactory.fromHostnameAndPath(miwSettings.host(), bpn).toString();

        VerifiableCredential vc1 = TestUtils.issueRandomVC(wallet.getDid(), miwSettings.authorityWalletDid(), miwSettings, objectMapper, revocationClient, restTemplate);
        VerifiableCredential vc2 = TestUtils.issueRandomVC(wallet.getDid(), miwSettings.authorityWalletDid(), miwSettings, objectMapper, revocationClient, restTemplate);
        VerifiableCredential vc3 = TestUtils.issueRandomVC(wallet.getDid(), miwSettings.authorityWalletDid(), miwSettings, objectMapper, revocationClient, restTemplate);
        VerifiableCredential vc4 = TestUtils.issueRandomVC(wallet.getDid(), miwSettings.authorityWalletDid(), miwSettings, objectMapper, revocationClient, restTemplate);
        VerifiableCredential vc5 = TestUtils.issueRandomVC(wallet.getDid(), miwSettings.authorityWalletDid(), miwSettings, objectMapper, revocationClient, restTemplate);

        //create request
        Map<String, Object> request = new HashMap<>();
        request.put(StringPool.HOLDER_IDENTIFIER, wallet.getDid());
        request.put(StringPool.VERIFIABLE_CREDENTIALS, List.of(objectMapper.readValue(vc1.toJson(), Map.class),
                objectMapper.readValue(vc2.toJson(), Map.class),
                objectMapper.readValue(vc3.toJson(), Map.class),
                objectMapper.readValue(vc4.toJson(), Map.class),
                objectMapper.readValue(vc5.toJson(), Map.class)
        ));
        try (MockedStatic<LinkedDataProofValidation> utils = Mockito.mockStatic(LinkedDataProofValidation.class)) {
            //mock VC verification
            //mock setup
            mockVCSignatureVarification(utils, true);

            ///mock revocation
            mockRevocationVerification(false);

            Assertions.assertDoesNotThrow(() -> {
                Map<String, Object> presentation = presentationService.createPresentation(request, true, true, true, audience, bpn);

                String jwt = presentation.get("vp").toString();
                SignedJWT signedJWT = SignedJWT.parse(jwt);
                JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();
                String iss = claimsSet.getStringClaim("iss");

                //issuer of VP is must be holder of VP
                Assertions.assertEquals(iss, did);
            });
            Mockito.reset(revocationClient);
        }

    }

    private ResponseEntity<Map> createBpnVCAsJwt(String bpn, String audience) throws JsonProcessingException {
        Map<String, Object> request = getIssueVPRequest(bpn);

        HttpHeaders headers = AuthenticationUtils.getValidUserHttpHeaders(bpn);
        headers.put(HttpHeaders.CONTENT_TYPE, List.of(MediaType.APPLICATION_JSON_VALUE));

        HttpEntity<String> entity = new HttpEntity<>(objectMapper.writeValueAsString(request), headers);

        ResponseEntity<Map> vpResponse = restTemplate.exchange(RestURI.API_PRESENTATIONS + "?asJwt={asJwt}&audience={audience}", HttpMethod.POST, entity, Map.class, true, audience);
        return vpResponse;
    }


    @Test
    void createPresentationAsJsonLD201() throws JsonProcessingException {

        String bpn = UUID.randomUUID().toString();
        String didWeb = DidWebFactory.fromHostnameAndPath(miwSettings.host(), bpn).toString();

        Map<String, Object> request = getIssueVPRequest(bpn);

        HttpHeaders headers = AuthenticationUtils.getValidUserHttpHeaders(bpn);
        headers.put(HttpHeaders.CONTENT_TYPE, List.of(MediaType.APPLICATION_JSON_VALUE));

        HttpEntity<String> entity = new HttpEntity<>(objectMapper.writeValueAsString(request), headers);

        ResponseEntity<Map> vpResponse = restTemplate.exchange(RestURI.API_PRESENTATIONS, HttpMethod.POST, entity, Map.class);
        Assertions.assertEquals(vpResponse.getStatusCode().value(), HttpStatus.CREATED.value());

    }

    @Test
    void createPresentationWithInvalidBPNAccess403() throws JsonProcessingException {
        String bpn = UUID.randomUUID().toString();
        String didWeb = DidWebFactory.fromHostnameAndPath(miwSettings.host(), bpn).toString();

        Map<String, Object> request = getIssueVPRequest(bpn);

        HttpHeaders headers = AuthenticationUtils.getValidUserHttpHeaders("invalid bpn");
        headers.put(HttpHeaders.CONTENT_TYPE, List.of(MediaType.APPLICATION_JSON_VALUE));

        HttpEntity<String> entity = new HttpEntity<>(objectMapper.writeValueAsString(request), headers);

        ResponseEntity<Map> vpResponse = restTemplate.exchange(RestURI.API_PRESENTATIONS + "?asJwt={asJwt}&audience={audience}", HttpMethod.POST, entity, Map.class, true, "companyA");
        Assertions.assertEquals(vpResponse.getStatusCode().value(), HttpStatus.NOT_FOUND.value());
    }

    @NotNull
    private Map<String, Object> getIssueVPRequest(String bpn) throws JsonProcessingException {
        String baseBpn = miwSettings.authorityWalletBpn();
        ResponseEntity<String> response = TestUtils.createWallet(bpn, bpn, restTemplate, baseBpn);
        Assertions.assertEquals(response.getStatusCode().value(), HttpStatus.CREATED.value());
        Wallet wallet = TestUtils.getWalletFromString(response.getBody());

        //get BPN credentials
        List<HoldersCredential> credentials = holdersCredentialRepository.getByHolderDidAndType(wallet.getDid(), MIWVerifiableCredentialType.BPN_CREDENTIAL);

        Map<String, Object> map = objectMapper.readValue(credentials.get(0).getData().toJson(), Map.class);

        //create request
        Map<String, Object> request = new HashMap<>();
        request.put(StringPool.HOLDER_IDENTIFIER, wallet.getDid());
        request.put(StringPool.VERIFIABLE_CREDENTIALS, List.of(map));
        return request;
    }

    private void mockRevocationVerification(boolean revoked) {
        Mockito.reset(revocationClient);
        StatusVerificationResponse statusVerificationResponse = new StatusVerificationResponse();
        statusVerificationResponse.setRevoked(revoked);
        statusVerificationResponse.setSuspended(false);
        Mockito.when(revocationClient.verify(Mockito.any(StatusVerificationRequest.class))).thenReturn(statusVerificationResponse);
    }

    @NotNull
    private ResponseEntity<Map> getIssueVPRequestWithShortExpiry(String bpn, String audience) throws JsonProcessingException {
        String baseBpn = miwSettings.authorityWalletBpn();
        ResponseEntity<String> response = TestUtils.createWallet(bpn, bpn, restTemplate, baseBpn);
        Assertions.assertEquals(response.getStatusCode().value(), HttpStatus.CREATED.value());
        Wallet wallet = TestUtils.getWalletFromString(response.getBody());

        //create VC
        HttpHeaders headers = AuthenticationUtils.getValidUserHttpHeaders(miwSettings.authorityWalletBpn());
        String type = VerifiableCredentialType.MEMBERSHIP_CREDENTIAL;
        Instant vcExpiry = Instant.now().minusSeconds(60);

        VerifiableCredential verifiableCredential = TestUtils.issueRandomVC(wallet.getBpn(), wallet.getDid(), miwSettings, objectMapper, revocationClient, restTemplate);

        Map<String, Object> map = objectMapper.readValue(verifiableCredential.toJson(), Map.class);

        //create request
        Map<String, Object> request = new HashMap<>();
        request.put(StringPool.HOLDER_IDENTIFIER, wallet.getDid());
        request.put(StringPool.VERIFIABLE_CREDENTIALS, List.of(map));

        headers = AuthenticationUtils.getValidUserHttpHeaders(bpn);
        headers.put(HttpHeaders.CONTENT_TYPE, List.of(MediaType.APPLICATION_JSON_VALUE));

        HttpEntity<String> entity = new HttpEntity<>(objectMapper.writeValueAsString(request), headers);

        ResponseEntity<Map> vpResponse = restTemplate.exchange(RestURI.API_PRESENTATIONS + "?asJwt={asJwt}&audience={audience}", HttpMethod.POST, entity, Map.class, true, audience);
        return vpResponse;
    }

    private static void mockVCSignatureVarification(MockedStatic<LinkedDataProofValidation> utils, boolean validSignature) {
        LinkedDataProofValidation mock = Mockito.mock(LinkedDataProofValidation.class);
        utils.when(() -> {
            LinkedDataProofValidation.newInstance(Mockito.any(SignatureType.class), Mockito.any(DidDocumentResolverRegistryImpl.class));
        }).thenReturn(mock);
        Mockito.when(mock.verifiyProof(Mockito.any(VerifiableCredential.class))).thenReturn(validSignature);
    }

}