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

package org.eclipse.tractusx.managedidentitywallets.utils;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.eclipse.tractusx.managedidentitywallets.config.MIWSettings;
import org.eclipse.tractusx.managedidentitywallets.config.RevocationSettings;
import org.eclipse.tractusx.managedidentitywallets.constant.MIWVerifiableCredentialType;
import org.eclipse.tractusx.managedidentitywallets.constant.RestURI;
import org.eclipse.tractusx.managedidentitywallets.constant.StringPool;
import org.eclipse.tractusx.managedidentitywallets.dao.entity.HoldersCredential;
import org.eclipse.tractusx.managedidentitywallets.dao.entity.IssuersCredential;
import org.eclipse.tractusx.managedidentitywallets.dao.entity.Wallet;
import org.eclipse.tractusx.managedidentitywallets.dao.repository.HoldersCredentialRepository;
import org.eclipse.tractusx.managedidentitywallets.dao.repository.IssuersCredentialRepository;
import org.eclipse.tractusx.managedidentitywallets.dao.repository.WalletRepository;
import org.eclipse.tractusx.managedidentitywallets.dto.CreateWalletRequest;
import org.eclipse.tractusx.managedidentitywallets.dto.IssueFrameworkCredentialRequest;
import org.eclipse.tractusx.managedidentitywallets.dto.IssueMembershipCredentialRequest;
import org.eclipse.tractusx.managedidentitywallets.revocation.client.RevocationClient;
import org.eclipse.tractusx.managedidentitywallets.revocation.model.StatusEntryRequest;
import org.eclipse.tractusx.ssi.lib.model.did.DidDocument;
import org.eclipse.tractusx.ssi.lib.model.verifiable.credential.*;
import org.jetbrains.annotations.NotNull;
import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.jupiter.api.Assertions;
import org.mockito.Mockito;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.*;

import java.net.URI;
import java.time.Instant;
import java.util.*;

/**
 * The type Test utils.
 */
public class TestUtils {


    /**
     * Create wallet response entity.
     *
     * @param bpn          the bpn
     * @param name         the name
     * @param testTemplate the test template
     * @param baseBPN      the base bpn
     * @return the response entity
     */
    public static ResponseEntity<String> createWallet(String bpn, String name, TestRestTemplate testTemplate, String baseBPN) {
        HttpHeaders headers = AuthenticationUtils.getValidUserHttpHeaders(baseBPN);

        CreateWalletRequest request = CreateWalletRequest.builder().bpn(bpn).name(name).build();

        HttpEntity<CreateWalletRequest> entity = new HttpEntity<>(request, headers);

        ResponseEntity<String> exchange = testTemplate.exchange(RestURI.WALLETS, HttpMethod.POST, entity, String.class);
        return exchange;

    }

    /**
     * Create wallet wallet.
     *
     * @param bpn              the bpn
     * @param did              the did
     * @param walletRepository the wallet repository
     * @return the wallet
     */
    public static Wallet createWallet(String bpn, String did, WalletRepository walletRepository) {
        String didDocument = """
                {
                  "id": "did:web:localhost:bpn123124",
                  "verificationMethod": [
                    {
                      "publicKeyMultibase": "z9mo3TUPvEntiBQtHYVXXy5DfxLGgaHa84ZT6Er2qWs4y",
                      "controller": "did:web:localhost%3Abpn123124",
                      "id": "did:web:localhost%3Abpn123124#key-1",
                      "type": "Ed25519VerificationKey2020"
                    }
                  ],
                  "@context": "https://www.w3.org/ns/did/v1"
                }
                """;

        Wallet wallet = Wallet.builder()
                .bpn(bpn)
                .did(did)
                .didDocument(DidDocument.fromJson(didDocument))
                .algorithm(StringPool.ED_25519)
                .name(bpn)
                .build();
        return walletRepository.save(wallet);
    }

    /**
     * Check vc.
     *
     * @param verifiableCredential the verifiable credential
     * @param miwSettings          the miw settings
     */
    public static void checkVC(VerifiableCredential verifiableCredential, MIWSettings miwSettings) {
        List<URI> links = new ArrayList<>(miwSettings.vcContexts());

        Assertions.assertEquals(verifiableCredential.getContext().size(), miwSettings.vcContexts().size());
        for (URI link : verifiableCredential.getContext()) {
            Assertions.assertTrue(links.contains(link));
        }
        //check expiry date
        Assertions.assertEquals(0, verifiableCredential.getExpirationDate().compareTo(miwSettings.vcExpiryDate().toInstant()));
    }

    /**
     * Check vc.
     *
     * @param verifiableCredential the verifiable credential
     * @param miwSettings          the miw settings
     * @param revocationSettings   the revocation settings
     */
    public static void checkVC(VerifiableCredential verifiableCredential, MIWSettings miwSettings, RevocationSettings revocationSettings) {
        List<URI> links = new ArrayList<>(miwSettings.vcContexts());
        if (!Objects.isNull(verifiableCredential.getVerifiableCredentialStatus())) {
            //in case of revocation, there will be revocation context url
            Assertions.assertEquals(verifiableCredential.getContext().size(), miwSettings.vcContexts().size() + 1);
            links.add(revocationSettings.contextUrl());
        } else {
            Assertions.assertEquals(verifiableCredential.getContext().size(), miwSettings.vcContexts().size());
        }
        for (URI link : verifiableCredential.getContext()) {
            Assertions.assertTrue(links.contains(link));
        }
        //check expiry date
        Assertions.assertEquals(0, verifiableCredential.getExpirationDate().compareTo(miwSettings.vcExpiryDate().toInstant()));
    }

    /**
     * Issue membership vc response entity.
     *
     * @param restTemplate  the rest template
     * @param bpn           the bpn
     * @param baseWalletBpn the base wallet bpn
     * @return the response entity
     */
    public static ResponseEntity<String> issueMembershipVC(TestRestTemplate restTemplate, String bpn, String baseWalletBpn) {
        HttpHeaders headers = AuthenticationUtils.getValidUserHttpHeaders(baseWalletBpn);
        IssueMembershipCredentialRequest request = IssueMembershipCredentialRequest.builder().bpn(bpn).build();
        HttpEntity<IssueMembershipCredentialRequest> entity = new HttpEntity<>(request, headers);

        return restTemplate.exchange(RestURI.CREDENTIALS_ISSUER_MEMBERSHIP, HttpMethod.POST, entity, String.class);
    }

    /**
     * Gets issue framework credential request.
     *
     * @param bpn  the bpn
     * @param type the type
     * @return the issue framework credential request
     */
    public static IssueFrameworkCredentialRequest getIssueFrameworkCredentialRequest(String bpn, String type) {
        IssueFrameworkCredentialRequest twinRequest = IssueFrameworkCredentialRequest.builder()
                .contractTemplate("http://localhost")
                .contractVersion("v1")
                .type(type)
                .holderIdentifier(bpn)
                .build();
        return twinRequest;
    }


    /**
     * Gets wallet from string.
     *
     * @param body the body
     * @return the wallet from string
     * @throws JsonProcessingException the json processing exception
     */
    public static Wallet getWalletFromString(String body) throws JsonProcessingException {
        JSONObject jsonObject = new JSONObject(body);
        //convert DidDocument
        JSONObject didDocument = jsonObject.getJSONObject(StringPool.DID_DOCUMENT);
        jsonObject.remove(StringPool.DID_DOCUMENT);

        JSONArray credentialArray = null;
        if (!jsonObject.isNull(StringPool.VERIFIABLE_CREDENTIALS)) {
            credentialArray = jsonObject.getJSONArray(StringPool.VERIFIABLE_CREDENTIALS);
            jsonObject.remove(StringPool.VERIFIABLE_CREDENTIALS);
        }

        ObjectMapper objectMapper = new ObjectMapper();
        Wallet wallet1 = objectMapper.readValue(jsonObject.toString(), Wallet.class);
        wallet1.setDidDocument(DidDocument.fromJson(didDocument.toString()));

        //convert VC
        if (credentialArray != null) {
            List<VerifiableCredential> verifiableCredentials = new ArrayList<>(credentialArray.length());
            for (int i = 0; i < credentialArray.length(); i++) {
                JSONObject object = credentialArray.getJSONObject(i);
                verifiableCredentials.add(new VerifiableCredential(objectMapper.readValue(object.toString(), Map.class)));
            }
            wallet1.setVerifiableCredentials(verifiableCredentials);
        }
        System.out.println("wallet -- >" + wallet1.getBpn());
        return wallet1;
    }


    /**
     * Gets summary credential id.
     *
     * @param holderDID                   the holder did
     * @param holdersCredentialRepository the holders credential repository
     * @return the summary credential id
     */
    public static String getSummaryCredentialId(String holderDID, HoldersCredentialRepository holdersCredentialRepository) {
        List<HoldersCredential> holderVCs = holdersCredentialRepository.getByHolderDidAndType(holderDID, MIWVerifiableCredentialType.SUMMARY_CREDENTIAL);
        Assertions.assertEquals(1, holderVCs.size());
        return holderVCs.get(0).getData().getId().toString();
    }

    /**
     * Check summary credential.
     *
     * @param issuerDID                   the issuer did
     * @param holderDID                   the holder did
     * @param holdersCredentialRepository the holders credential repository
     * @param issuersCredentialRepository the issuers credential repository
     * @param type                        the type
     * @param previousSummaryCredentialId the previous summary credential id
     */
    public static void checkSummaryCredential(String issuerDID, String holderDID, HoldersCredentialRepository holdersCredentialRepository,
                                              IssuersCredentialRepository issuersCredentialRepository, String type, String previousSummaryCredentialId) {

        //get VC from holder of Summary type
        List<HoldersCredential> holderVCs = holdersCredentialRepository.getByHolderDidAndType(holderDID, MIWVerifiableCredentialType.SUMMARY_CREDENTIAL);
        Assertions.assertEquals(1, holderVCs.size());
        VerifiableCredential vc = holderVCs.get(0).getData();
        VerifiableCredentialSubject subject = vc.getCredentialSubject().get(0);

        //check if type is in items
        List<String> list = (List<String>) subject.get(StringPool.ITEMS);
        Assertions.assertTrue(list.contains(type));

        //check in issuer table
        List<IssuersCredential> issuerVCs = issuersCredentialRepository.getByIssuerDidAndHolderDidAndType(issuerDID, holderDID,
                MIWVerifiableCredentialType.SUMMARY_CREDENTIAL);
        IssuersCredential issuersCredential = issuerVCs.stream()
                .filter(issuerVC -> issuerVC.getCredentialId().equalsIgnoreCase(vc.getId().toString())).findFirst()
                .orElse(null);
        Assertions.assertNotNull(issuersCredential);
        IssuersCredential previousIssuersCredential = issuerVCs.stream()
                .filter(issuerVC -> issuerVC.getCredentialId().equalsIgnoreCase(previousSummaryCredentialId)).findFirst()
                .orElse(null);
        Assertions.assertNotNull(previousIssuersCredential);
    }


    /**
     * Gets verifiable credentials.
     *
     * @param response     the response
     * @param objectMapper the object mapper
     * @return the verifiable credentials
     * @throws JsonProcessingException the json processing exception
     */
    @NotNull
    public static List<VerifiableCredential> getVerifiableCredentials(ResponseEntity<String> response, ObjectMapper objectMapper) throws JsonProcessingException {
        Map<String, Object> map = objectMapper.readValue(response.getBody(), Map.class);

        List<Map<String, Object>> vcs = (List<Map<String, Object>>) map.get("content");

        List<VerifiableCredential> credentialList = new ArrayList<>();
        for (Map<String, Object> stringObjectMap : vcs) {
            credentialList.add(new VerifiableCredential(stringObjectMap));
        }
        return credentialList;
    }


    /**
     * Gets status listentry.
     *
     * @return the status listentry
     */
    @NotNull
    public static Map<String, Object> getStatusListentry() {
        Map<String, Object> statusMap = new HashMap<>();
        statusMap.put(VerifiableCredentialStatusList2021Entry.TYPE, "StatusList2021Entry");
        statusMap.put(VerifiableCredentialStatusList2021Entry.ID, "http://localhost:8085/api/v1/revocations/credentials/did-revocation#0");
        statusMap.put(VerifiableCredentialStatusList2021Entry.STATUS_PURPOSE, "revocation");
        statusMap.put(VerifiableCredentialStatusList2021Entry.STATUS_LIST_INDEX, "1");
        statusMap.put(VerifiableCredentialStatusList2021Entry.STATUS_LIST_CREDENTIAL, "http://localhost:8085/api/v1/revocations/credentials/did-revocation");
        return statusMap;
    }


    /**
     * Issue random vc verifiable credential.
     *
     * @param holderDid        the holder did
     * @param issuerDid        the issuer did
     * @param miwSettings      the miw settings
     * @param objectMapper     the object mapper
     * @param revocationClient the revocation client
     * @param restTemplate     the rest template
     * @return the verifiable credential
     * @throws JsonProcessingException the json processing exception
     */
    public static VerifiableCredential issueRandomVC(String holderDid, String issuerDid, MIWSettings miwSettings, ObjectMapper objectMapper, RevocationClient revocationClient, TestRestTemplate restTemplate) throws JsonProcessingException {

        String type = UUID.randomUUID().toString();
        //VC Bulider
        VerifiableCredentialBuilder verifiableCredentialBuilder =
                new VerifiableCredentialBuilder();

        //VC Subject
        VerifiableCredentialSubject verifiableCredentialSubject =
                new VerifiableCredentialSubject(Map.of("type", UUID.randomUUID().toString()));

        //Using Builder
        VerifiableCredential credentialWithoutProof =
                verifiableCredentialBuilder
                        .id(URI.create(issuerDid + "#" + UUID.randomUUID()))
                        .context(miwSettings.vcContexts())
                        .type(List.of(VerifiableCredentialType.VERIFIABLE_CREDENTIAL, type))
                        .issuer(URI.create(issuerDid)) //issuer must be base wallet
                        .expirationDate(miwSettings.vcExpiryDate().toInstant())
                        .issuanceDate(Instant.now())
                        .credentialSubject(verifiableCredentialSubject)
                        .build();

        Map<String, Objects> map = objectMapper.readValue(credentialWithoutProof.toJson(), Map.class);

        Map<String, Object> statusMap = TestUtils.getStatusListentry();

        //mock revocation service
        Mockito.when(revocationClient.statusEntry(Mockito.anyString(), Mockito.any(StatusEntryRequest.class))).thenReturn(statusMap);

        //issue Revocable VC
        HttpHeaders headers = AuthenticationUtils.getValidUserHttpHeaders(miwSettings.authorityWalletBpn());
        HttpEntity<Map> entity = new HttpEntity<>(map, headers);
        ResponseEntity<String> response = restTemplate.exchange(RestURI.ISSUERS_CREDENTIALS + "?holderDid={did}&revocable={revocable}", HttpMethod.POST, entity, String.class, holderDid, true);
        Assertions.assertEquals(HttpStatus.CREATED.value(), response.getStatusCode().value());
        return new VerifiableCredential(objectMapper.readValue(response.getBody(), Map.class));
    }
}