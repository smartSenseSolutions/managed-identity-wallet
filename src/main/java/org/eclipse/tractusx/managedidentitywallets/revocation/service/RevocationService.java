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

package org.eclipse.tractusx.managedidentitywallets.revocation.service;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.text.StringEscapeUtils;
import org.eclipse.tractusx.managedidentitywallets.config.RevocationSettings;
import org.eclipse.tractusx.managedidentitywallets.constant.StringPool;
import org.eclipse.tractusx.managedidentitywallets.revocation.client.RevocationClient;
import org.eclipse.tractusx.managedidentitywallets.revocation.model.*;
import org.eclipse.tractusx.managedidentitywallets.utils.Validate;
import org.eclipse.tractusx.ssi.lib.model.verifiable.credential.VerifiableCredentialStatusList2021Entry;
import org.springframework.stereotype.Service;

import java.util.Map;

/**
 * The type Revocation service.
 */
@Service
@Slf4j
public class RevocationService {

    private final RevocationClient revocationClient;

    private final String revocationHost;

    public RevocationService(RevocationClient revocationClient, RevocationSettings revocationSettings) {
        this.revocationClient = revocationClient;
        revocationHost = revocationSettings.host() + "/api/v1/revocations/credentials";

    }

    /**
     * Status entry for suspension verifiable credential status list 2021 entry.
     *
     * @param issuerBPN the issuer bpn
     * @return the verifiable credential status list 2021 entry
     */
    public VerifiableCredentialStatusList2021Entry statusEntryForSuspension(String issuerBPN) {
        return statusEntry(issuerBPN, StringPool.SUSPENSION);
    }

    /**
     * Status entry for revocation verifiable credential status list 2021 entry.
     *
     * @param issuerBPN the issuer bpn
     * @return the verifiable credential status list 2021 entry
     */
    public VerifiableCredentialStatusList2021Entry statusEntryForRevocation(String issuerBPN) {
        return statusEntry(issuerBPN, StringPool.REVOCATION);
    }

    /**
     * Verify status status verification response.
     *
     * @param statusList2021Entry the status list 2021 entry
     * @return the status verification response
     */
    public StatusVerificationResponse verifyStatus(VerifiableCredentialStatusList2021Entry statusList2021Entry) {
        StatusVerificationRequest statusVerificationRequest = StatusVerificationRequest.builder()
                .credentialStatus(statusList2021Entry)
                .build();
        return revocationClient.verify(statusVerificationRequest);
    }

    /**
     * Revoke credential.
     *
     * @param statusList2021Entry the status list 2021 entry
     */
    public void revokeCredential(VerifiableCredentialStatusList2021Entry statusList2021Entry) {
        RevocationRequest request = RevocationRequest.builder()
                .credentialStatus(statusList2021Entry)
                .build();
        revocationClient.revoke(request);
        log.debug("Credential revoked");
    }

    /**
     * Suspend credential.
     *
     * @param statusList2021Entry the status list 2021 entry
     */
    public void suspendCredential(VerifiableCredentialStatusList2021Entry statusList2021Entry) {
        SuspendRequest request = SuspendRequest.builder()
                .credentialStatus(statusList2021Entry)
                .build();
        revocationClient.suspend(request);
        log.debug("Credential suspended");
    }

    private VerifiableCredentialStatusList2021Entry statusEntry(String issuerBPN, String purpose) {
        Validate.isFalse(VerifiableCredentialStatusList2021Entry.VALID_STATUS_PURPOSES.contains(purpose)).launch(new IllegalArgumentException("Invalid purpose: " + purpose));
        StatusEntryRequest statusEntryRequest = StatusEntryRequest.builder()
                .credentialUrl(revocationHost)
                .purpose(purpose)
                .build();
        Map<String, Object> map = revocationClient.statusEntry(issuerBPN, statusEntryRequest);
        VerifiableCredentialStatusList2021Entry verifiableCredentialStatusList2021Entry = new VerifiableCredentialStatusList2021Entry(map);
        log.debug("status list entry done for bpn ->{}", StringEscapeUtils.escapeJava(issuerBPN));
        return verifiableCredentialStatusList2021Entry;
    }
}
