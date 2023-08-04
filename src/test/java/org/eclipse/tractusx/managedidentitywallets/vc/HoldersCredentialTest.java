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

package org.eclipse.tractusx.managedidentitywallets.vc;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.teketik.test.mockinbean.MockInBean;
import org.eclipse.tractusx.managedidentitywallets.ManagedIdentityWalletsApplication;
import org.eclipse.tractusx.managedidentitywallets.config.MIWSettings;
import org.eclipse.tractusx.managedidentitywallets.config.RevocationSettings;
import org.eclipse.tractusx.managedidentitywallets.config.TestContextInitializer;
import org.eclipse.tractusx.managedidentitywallets.constant.MIWVerifiableCredentialType;
import org.eclipse.tractusx.managedidentitywallets.constant.RestURI;
import org.eclipse.tractusx.managedidentitywallets.constant.StringPool;
import org.eclipse.tractusx.managedidentitywallets.controller.IssuersCredentialController;
import org.eclipse.tractusx.managedidentitywallets.dao.entity.HoldersCredential;
import org.eclipse.tractusx.managedidentitywallets.dao.repository.HoldersCredentialRepository;
import org.eclipse.tractusx.managedidentitywallets.dao.repository.WalletRepository;
import org.eclipse.tractusx.managedidentitywallets.dto.CreateWalletRequest;
import org.eclipse.tractusx.managedidentitywallets.dto.IssueFrameworkCredentialRequest;
import org.eclipse.tractusx.managedidentitywallets.exception.BadDataException;
import org.eclipse.tractusx.managedidentitywallets.revocation.client.RevocationClient;
import org.eclipse.tractusx.managedidentitywallets.revocation.model.RevocationRequest;
import org.eclipse.tractusx.managedidentitywallets.revocation.model.StatusEntryRequest;
import org.eclipse.tractusx.managedidentitywallets.revocation.model.StatusVerificationRequest;
import org.eclipse.tractusx.managedidentitywallets.revocation.model.StatusVerificationResponse;
import org.eclipse.tractusx.managedidentitywallets.revocation.service.RevocationService;
import org.eclipse.tractusx.managedidentitywallets.utils.AuthenticationUtils;
import org.eclipse.tractusx.managedidentitywallets.utils.TestUtils;
import org.eclipse.tractusx.ssi.lib.did.resolver.DidDocumentResolverRegistryImpl;
import org.eclipse.tractusx.ssi.lib.did.web.DidWebFactory;
import org.eclipse.tractusx.ssi.lib.model.verifiable.credential.*;
import org.eclipse.tractusx.ssi.lib.proof.LinkedDataProofValidation;
import org.eclipse.tractusx.ssi.lib.proof.SignatureType;
import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.*;
import org.springframework.test.context.ContextConfiguration;

import java.net.URI;
import java.time.Instant;
import java.util.*;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.DEFINED_PORT, classes = {ManagedIdentityWalletsApplication.class})
@ContextConfiguration(initializers = {TestContextInitializer.class})
@ExtendWith(MockitoExtension.class)
class HoldersCredentialTest {

    @Autowired
    private HoldersCredentialRepository holdersCredentialRepository;
    @Autowired
    private ObjectMapper objectMapper;
    @Autowired
    private MIWSettings miwSettings;
    @Autowired
    private RevocationSettings revocationSettings;
    @Autowired
    private WalletRepository walletRepository;
    @Autowired
    private TestRestTemplate restTemplate;

    @Autowired
    private IssuersCredentialController credentialController;

    @MockInBean(RevocationService.class)
    private RevocationClient revocationClient;


    @Test
    void issueCredentialTestWithInvalidBPNAccess403() throws JsonProcessingException {
        String bpn = UUID.randomUUID().toString();
        String did = DidWebFactory.fromHostnameAndPath(miwSettings.host(), bpn).toString();
        String type = "TestCredential";
        HttpHeaders headers = AuthenticationUtils.getValidUserHttpHeaders("not valid BPN");

        ResponseEntity<String> response = issueVC(bpn, did, type, headers, false, Map.of());


        Assertions.assertEquals(HttpStatus.FORBIDDEN.value(), response.getStatusCode().value());
    }


    @Test
    void issueRevocableCredentialTest200() throws JsonProcessingException {
        String bpn = UUID.randomUUID().toString();
        String did = DidWebFactory.fromHostnameAndPath(miwSettings.host(), bpn).toString();
        String type = "TestCredential";
        HttpHeaders headers = AuthenticationUtils.getValidUserHttpHeaders(bpn);

        Map<String, Object> statusMap = TestUtils.getStatusListentry();
        ResponseEntity<String> response = issueVC(bpn, did, type, headers, true, statusMap);

        Assertions.assertEquals(HttpStatus.CREATED.value(), response.getStatusCode().value());
        VerifiableCredential verifiableCredential = new VerifiableCredential(new ObjectMapper().readValue(response.getBody(), Map.class));
        Assertions.assertNotNull(verifiableCredential.getProof());

        List<HoldersCredential> credentials = holdersCredentialRepository.getByHolderDidAndType(did, type);
        Assertions.assertFalse(credentials.isEmpty());
        TestUtils.checkVC(credentials.get(0).getData(), miwSettings, revocationSettings);
        Assertions.assertTrue(credentials.get(0).isSelfIssued());
        Assertions.assertFalse(credentials.get(0).isStored());

        //check status list
        Assertions.assertNotNull(verifiableCredential.getVerifiableCredentialStatus());
        VerifiableCredentialStatusList2021Entry verifiableCredentialStatus = (VerifiableCredentialStatusList2021Entry) verifiableCredential.getVerifiableCredentialStatus();

        //check status list values
        Assertions.assertEquals(verifiableCredentialStatus.getId().toString(), statusMap.get(VerifiableCredentialStatusList2021Entry.ID).toString());
        Assertions.assertEquals(verifiableCredentialStatus.getType(), statusMap.get(VerifiableCredentialStatusList2021Entry.TYPE).toString());
        Assertions.assertEquals(verifiableCredentialStatus.getStatusPurpose(), statusMap.get(VerifiableCredentialStatusList2021Entry.STATUS_PURPOSE).toString());
        Assertions.assertEquals(verifiableCredentialStatus.getStatusListIndex(), Integer.parseInt(statusMap.get(VerifiableCredentialStatusList2021Entry.STATUS_LIST_INDEX).toString()));
        Assertions.assertEquals(verifiableCredentialStatus.getStatusListCredential().toString(), statusMap.get(VerifiableCredentialStatusList2021Entry.STATUS_LIST_CREDENTIAL).toString());

    }


    @Test
    void getCredentialsTest403() {

        HttpHeaders headers = AuthenticationUtils.getInvalidUserHttpHeaders();

        HttpEntity<CreateWalletRequest> entity = new HttpEntity<>(headers);

        ResponseEntity<Map> response = restTemplate.exchange(RestURI.CREDENTIALS, HttpMethod.GET, entity, Map.class);

        Assertions.assertEquals(HttpStatus.FORBIDDEN.value(), response.getStatusCode().value());
    }

    @Test
    void getCredentials200() throws com.fasterxml.jackson.core.JsonProcessingException {


        String baseDID = miwSettings.authorityWalletDid();
        String bpn = UUID.randomUUID().toString();
        String did = DidWebFactory.fromHostnameAndPath(miwSettings.host(), bpn).toString();
        HttpHeaders headers = AuthenticationUtils.getValidUserHttpHeaders(bpn);
        //save wallet
        TestUtils.createWallet(bpn, did, walletRepository);
        TestUtils.issueMembershipVC(restTemplate, bpn, miwSettings.authorityWalletBpn());
        String vcList = """
                [
                {"type":"TraceabilityCredential"},
                {"type":"SustainabilityCredential"},
                {"type":"ResiliencyCredential"},
                {"type":"QualityCredential"},
                {"type":"PcfCredential"}
                ]
                """;
        JSONArray jsonArray = new JSONArray(vcList);

        for (int i = 0; i < jsonArray.length(); i++) {
            JSONObject jsonObject = jsonArray.getJSONObject(i);
            IssueFrameworkCredentialRequest request = TestUtils.getIssueFrameworkCredentialRequest(bpn, jsonObject.get(StringPool.TYPE).toString());
            HttpEntity<IssueFrameworkCredentialRequest> entity = new HttpEntity<>(request, AuthenticationUtils.getValidUserHttpHeaders(miwSettings.authorityWalletBpn())); //ony base wallet can issue VC
            ResponseEntity<String> exchange = restTemplate.exchange(RestURI.API_CREDENTIALS_ISSUER_FRAMEWORK, HttpMethod.POST, entity, String.class);
            Assertions.assertEquals(exchange.getStatusCode().value(), HttpStatus.CREATED.value());
        }


        HttpEntity<Map> entity = new HttpEntity<>(headers);

        ResponseEntity<String> response = restTemplate.exchange(RestURI.CREDENTIALS + "?issuerIdentifier={did}"
                , HttpMethod.GET, entity, String.class, baseDID);
        List<VerifiableCredential> credentialList = TestUtils.getVerifiableCredentials(response, objectMapper);
        Assertions.assertEquals(HttpStatus.OK.value(), response.getStatusCode().value());
        Assertions.assertEquals(7, Objects.requireNonNull(credentialList).size()); //5  framework + 1 BPN + 1 Summary

        response = restTemplate.exchange(RestURI.CREDENTIALS + "?credentialId={id}"
                , HttpMethod.GET, entity, String.class, credentialList.get(0).getId());
        credentialList = TestUtils.getVerifiableCredentials(response, objectMapper);
        Assertions.assertEquals(HttpStatus.OK.value(), response.getStatusCode().value());
        Assertions.assertEquals(1, Objects.requireNonNull(credentialList).size());

        List<String> list = new ArrayList<>();
        list.add(MIWVerifiableCredentialType.MEMBERSHIP_CREDENTIAL);
        response = restTemplate.exchange(RestURI.CREDENTIALS + "?type={list}"
                , HttpMethod.GET, entity, String.class, String.join(",", list));
        credentialList = TestUtils.getVerifiableCredentials(response, objectMapper);
        Assertions.assertEquals(HttpStatus.OK.value(), response.getStatusCode().value());
        Assertions.assertEquals(1, Objects.requireNonNull(credentialList).size());

        list = new ArrayList<>();
        list.add(MIWVerifiableCredentialType.SUMMARY_CREDENTIAL);
        response = restTemplate.exchange(RestURI.CREDENTIALS + "?type={list}"
                , HttpMethod.GET, entity, String.class, String.join(",", list));
        credentialList = TestUtils.getVerifiableCredentials(response, objectMapper);
        Assertions.assertEquals(HttpStatus.OK.value(), response.getStatusCode().value());
        Assertions.assertEquals(1, credentialList.size());
        VerifiableCredentialSubject subject = credentialList.get(0).getCredentialSubject().get(0);
        List<String> itemList = (List<String>) subject.get(StringPool.ITEMS);
        Assertions.assertTrue(itemList.contains(MIWVerifiableCredentialType.MEMBERSHIP_CREDENTIAL));
        for (int i = 0; i < jsonArray.length(); i++) {
            JSONObject jsonObject = jsonArray.getJSONObject(i);
            Assertions.assertTrue(itemList.contains(jsonObject.get(StringPool.TYPE).toString()));
        }

    }


    @Test
    void validateCredentialsWithInvalidVC() throws com.fasterxml.jackson.core.JsonProcessingException {
        //data setup
        Map<String, Object> map = issueVC();

        //service call
        try (MockedStatic<LinkedDataProofValidation> utils = Mockito.mockStatic(LinkedDataProofValidation.class)) {

            //mock setup
            LinkedDataProofValidation mock = Mockito.mock(LinkedDataProofValidation.class);
            utils.when(() -> {
                LinkedDataProofValidation.newInstance(Mockito.any(SignatureType.class), Mockito.any(DidDocumentResolverRegistryImpl.class));
            }).thenReturn(mock);
            Mockito.when(mock.verifiyProof(Mockito.any(VerifiableCredential.class))).thenReturn(false);

            Map<String, Object> stringObjectMap = credentialController.credentialsValidation(map, false, false).getBody();
            Assertions.assertFalse(Boolean.parseBoolean(stringObjectMap.get(StringPool.VALID).toString()));
        }
    }


    @Test
    @DisplayName("validate VC with date check true, it should return true")
    void validateCredentialsWithExpiryCheckTrue() throws com.fasterxml.jackson.core.JsonProcessingException {

        //data setup
        Map<String, Object> map = issueVC();

        //service call
        try (MockedStatic<LinkedDataProofValidation> utils = Mockito.mockStatic(LinkedDataProofValidation.class)) {

            //mock setup
            LinkedDataProofValidation mock = Mockito.mock(LinkedDataProofValidation.class);
            utils.when(() -> {
                LinkedDataProofValidation.newInstance(Mockito.any(SignatureType.class), Mockito.any(DidDocumentResolverRegistryImpl.class));
            }).thenReturn(mock);
            Mockito.when(mock.verifiyProof(Mockito.any(VerifiableCredential.class))).thenReturn(true);

            Map<String, Object> stringObjectMap = credentialController.credentialsValidation(map, true, false).getBody();
            Assertions.assertTrue(Boolean.parseBoolean(stringObjectMap.get(StringPool.VALID).toString()));
            Assertions.assertTrue(Boolean.parseBoolean(stringObjectMap.get(StringPool.VALIDATE_EXPIRY_DATE).toString()));
        }
    }

    @Test
    @DisplayName("validate VC with revocation check true assuming revocation service return revoked=false and after that revoked=true")
    void validateCredentialsWithRevocationTure() throws JsonProcessingException {

        //issue revocable VC
        String bpn = UUID.randomUUID().toString();
        String did = DidWebFactory.fromHostnameAndPath(miwSettings.host(), bpn).toString();
        String type = "TestCredential";
        HttpHeaders headers = AuthenticationUtils.getValidUserHttpHeaders(bpn);

        Map<String, Object> statusMap = TestUtils.getStatusListentry();
        ResponseEntity<String> response = issueVC(bpn, did, type, headers, true, statusMap);

        Assertions.assertEquals(HttpStatus.CREATED.value(), response.getStatusCode().value());

        VerifiableCredential verifiableCredential = new VerifiableCredential(new ObjectMapper().readValue(response.getBody(), Map.class));
        Map<String, Object> map = objectMapper.readValue(verifiableCredential.toJson(), Map.class);

        //service call
        try (MockedStatic<LinkedDataProofValidation> utils = Mockito.mockStatic(LinkedDataProofValidation.class)) {

            //mock setup
            LinkedDataProofValidation mock = Mockito.mock(LinkedDataProofValidation.class);
            utils.when(() -> {
                LinkedDataProofValidation.newInstance(Mockito.any(SignatureType.class), Mockito.any(DidDocumentResolverRegistryImpl.class));
            }).thenReturn(mock);

            //mock signature check
            Mockito.when(mock.verifiyProof(Mockito.any(VerifiableCredential.class))).thenReturn(true);

            //mock evocation client, return revoked = true
            Mockito.reset(revocationClient);
            StatusVerificationResponse statusVerificationResponse = new StatusVerificationResponse();
            statusVerificationResponse.setRevoked(false);
            statusVerificationResponse.setSuspended(false);
            Mockito.when(revocationClient.verify(Mockito.any(StatusVerificationRequest.class))).thenReturn(statusVerificationResponse);

            Map<String, Object> stringObjectMap = credentialController.credentialsValidation(map, false, true).getBody();
            Assertions.assertTrue(Boolean.parseBoolean(stringObjectMap.get(StringPool.VALID).toString()));
            Assertions.assertFalse(Boolean.parseBoolean(stringObjectMap.get(StringPool.REVOKED).toString()));
            Mockito.reset(revocationClient);

            //mock revocation to return revoked=ture
            statusVerificationResponse.setRevoked(true);
            Mockito.when(revocationClient.verify(Mockito.any(StatusVerificationRequest.class))).thenReturn(statusVerificationResponse);
            stringObjectMap = credentialController.credentialsValidation(map, false, true).getBody();
            Assertions.assertFalse(Boolean.parseBoolean(stringObjectMap.get(StringPool.VALID).toString()));
            Assertions.assertTrue(Boolean.parseBoolean(stringObjectMap.get(StringPool.REVOKED).toString()));
            Mockito.reset(revocationClient);
        }
    }


    @Test
    @DisplayName("validate VC which does not have status list entry and  with revocation check true, it should throw bad data exception")
    void validateCredentialsWithoutStatusListEntryWithRevocationTure() throws com.fasterxml.jackson.core.JsonProcessingException {

        //data setup
        Map<String, Object> map = issueVC();
        //modify expiry date
        Instant instant = Instant.now().minusSeconds(60);
        map.put("expirationDate", instant.toString());

        //service call
        try (MockedStatic<LinkedDataProofValidation> utils = Mockito.mockStatic(LinkedDataProofValidation.class)) {
            //mock setup
            LinkedDataProofValidation mock = Mockito.mock(LinkedDataProofValidation.class);
            utils.when(() -> {
                LinkedDataProofValidation.newInstance(Mockito.any(SignatureType.class), Mockito.any(DidDocumentResolverRegistryImpl.class));
            }).thenReturn(mock);
            Mockito.when(mock.verifiyProof(Mockito.any(VerifiableCredential.class))).thenReturn(true);
            Assertions.assertThrows(BadDataException.class, () -> {
                credentialController.credentialsValidation(map, false, true);
            });
        }
    }

    @Test
    @DisplayName("validate expired VC with date check false, it should return true")
    void validateCredentialsWithExpiryCheckFalse() throws com.fasterxml.jackson.core.JsonProcessingException {

        //data setup
        Map<String, Object> map = issueVC();
        //modify expiry date
        Instant instant = Instant.now().minusSeconds(60);
        map.put("expirationDate", instant.toString());


        //service call
        try (MockedStatic<LinkedDataProofValidation> utils = Mockito.mockStatic(LinkedDataProofValidation.class)) {

            //mock setup
            LinkedDataProofValidation mock = Mockito.mock(LinkedDataProofValidation.class);
            utils.when(() -> {
                LinkedDataProofValidation.newInstance(Mockito.any(SignatureType.class), Mockito.any(DidDocumentResolverRegistryImpl.class));
            }).thenReturn(mock);
            Mockito.when(mock.verifiyProof(Mockito.any(VerifiableCredential.class))).thenReturn(true);

            Map<String, Object> stringObjectMap = credentialController.credentialsValidation(map, false, false).getBody();
            Assertions.assertTrue(Boolean.parseBoolean(stringObjectMap.get(StringPool.VALID).toString()));
        }
    }


    @Test
    @DisplayName("validate expired VC with date check true, it should return false")
    void validateExpiredCredentialsWithExpiryCheckTrue() throws com.fasterxml.jackson.core.JsonProcessingException {

        //data setup
        Map<String, Object> map = issueVC();
        //modify expiry date
        Instant instant = Instant.now().minusSeconds(60);
        map.put("expirationDate", instant.toString());

        //service call
        try (MockedStatic<LinkedDataProofValidation> utils = Mockito.mockStatic(LinkedDataProofValidation.class)) {

            //mock setup
            LinkedDataProofValidation mock = Mockito.mock(LinkedDataProofValidation.class);
            utils.when(() -> {
                LinkedDataProofValidation.newInstance(Mockito.any(SignatureType.class), Mockito.any(DidDocumentResolverRegistryImpl.class));
            }).thenReturn(mock);
            Mockito.when(mock.verifiyProof(Mockito.any(VerifiableCredential.class))).thenReturn(true);

            Map<String, Object> stringObjectMap = credentialController.credentialsValidation(map, true, false).getBody();
            Assertions.assertFalse(Boolean.parseBoolean(stringObjectMap.get(StringPool.VALID).toString()));
            Assertions.assertFalse(Boolean.parseBoolean(stringObjectMap.get(StringPool.VALIDATE_EXPIRY_DATE).toString()));

        }
    }

    @Test
    void revokeVC() throws JsonProcessingException {

        //issue revocable VC
        String bpn = UUID.randomUUID().toString();
        String did = DidWebFactory.fromHostnameAndPath(miwSettings.host(), bpn).toString();
        String type = "TestCredential";
        HttpHeaders headers = AuthenticationUtils.getValidUserHttpHeaders(bpn);

        Map<String, Object> statusMap = TestUtils.getStatusListentry();
        ResponseEntity<String> response = issueVC(bpn, did, type, headers, true, statusMap);

        Assertions.assertEquals(HttpStatus.CREATED.value(), response.getStatusCode().value());

        VerifiableCredential verifiableCredential = new VerifiableCredential(new ObjectMapper().readValue(response.getBody(), Map.class));
        Map<String, Object> map = objectMapper.readValue(verifiableCredential.toJson(), Map.class);

        //service call
        try (MockedStatic<LinkedDataProofValidation> utils = Mockito.mockStatic(LinkedDataProofValidation.class)) {

            //mock setup
            LinkedDataProofValidation mock = Mockito.mock(LinkedDataProofValidation.class);
            utils.when(() -> {
                LinkedDataProofValidation.newInstance(Mockito.any(SignatureType.class), Mockito.any(DidDocumentResolverRegistryImpl.class));
            }).thenReturn(mock);

            //mock signature check
            Mockito.when(mock.verifiyProof(Mockito.any(VerifiableCredential.class))).thenReturn(true);

            //mock evocation client, return revoked = true
            Mockito.reset(revocationClient);

            Mockito.doNothing().when(revocationClient).revoke(Mockito.any(RevocationRequest.class));
            credentialController.credentialsRevoke(map).getBody();
            Mockito.reset(revocationClient);

            //mock revocation to return revoked=ture
            StatusVerificationResponse statusVerificationResponse = new StatusVerificationResponse();
            statusVerificationResponse.setSuspended(false);
            statusVerificationResponse.setRevoked(true);
            Mockito.when(revocationClient.verify(Mockito.any(StatusVerificationRequest.class))).thenReturn(statusVerificationResponse);
            Map<String, Object> stringObjectMap = credentialController.credentialsValidation(map, false, true).getBody();
            Assertions.assertFalse(Boolean.parseBoolean(stringObjectMap.get(StringPool.VALID).toString()));
            Assertions.assertTrue(Boolean.parseBoolean(stringObjectMap.get(StringPool.REVOKED).toString()));
            Mockito.reset(revocationClient);
        }
    }


    private Map<String, Object> issueVC() throws JsonProcessingException {
        String bpn = UUID.randomUUID().toString();
        HttpHeaders headers = AuthenticationUtils.getValidUserHttpHeaders(bpn);
        TestUtils.createWallet(bpn, "Test", restTemplate);
        ResponseEntity<String> vc = TestUtils.issueMembershipVC(restTemplate, bpn, miwSettings.authorityWalletBpn());
        VerifiableCredential verifiableCredential = new VerifiableCredential(new ObjectMapper().readValue(vc.getBody(), Map.class));
        Map<String, Object> map = objectMapper.readValue(verifiableCredential.toJson(), Map.class);
        return map;
    }


    private ResponseEntity<String> issueVC(String bpn, String did, String type, HttpHeaders headers, boolean revocable, Map<String, Object> statusMap) throws JsonProcessingException {
        //save wallet
        TestUtils.createWallet(bpn, did, restTemplate);

        // Create VC without proof
        //VC Bulider
        VerifiableCredentialBuilder verifiableCredentialBuilder =
                new VerifiableCredentialBuilder();

        //VC Subject
        VerifiableCredentialSubject verifiableCredentialSubject =
                new VerifiableCredentialSubject(Map.of("test", "test"));

        //Using Builder
        VerifiableCredential credentialWithoutProof =
                verifiableCredentialBuilder
                        .id(URI.create(did + "#" + UUID.randomUUID()))
                        .context(miwSettings.vcContexts())
                        .type(List.of(VerifiableCredentialType.VERIFIABLE_CREDENTIAL, type))
                        .issuer(URI.create(did)) //issuer must be base wallet
                        .expirationDate(miwSettings.vcExpiryDate().toInstant())
                        .issuanceDate(Instant.now())
                        .credentialSubject(verifiableCredentialSubject)
                        .build();


        if (revocable) {
            //mock revocation service
            Mockito.when(revocationClient.statusEntry(Mockito.anyString(), Mockito.any(StatusEntryRequest.class))).thenReturn(statusMap);
        }

        Map<String, Objects> map = objectMapper.readValue(credentialWithoutProof.toJson(), Map.class);
        HttpEntity<Map> entity = new HttpEntity<>(map, headers);
        ResponseEntity<String> response = restTemplate.exchange(RestURI.CREDENTIALS + "?revocable={revocable}", HttpMethod.POST, entity, String.class, revocable);
        return response;
    }
}
