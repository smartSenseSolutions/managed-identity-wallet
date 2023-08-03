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

package org.eclipse.tractusx.managedidentitywallets.revocation.client;

import org.eclipse.tractusx.managedidentitywallets.revocation.model.*;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * The interface Revocation client.
 */
@FeignClient(value = "revocation", url = "${miw.revocation.host}", configuration = ClientConfiguration.class)
public interface RevocationClient {

    /**
     * Status list entry for VC
     *
     * @param issuerId           the issuer id
     * @param statusEntryRequest the status entry request
     * @return the verifiable credential status list 2021 entry
     */
    @PostMapping(path = "/api/v1/revocations/statusEntry", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    Map<String, Object> statusEntry(@RequestParam(name = "issuerId") String issuerId, @RequestBody StatusEntryRequest statusEntryRequest);

    /**
     * Revoke VC.
     *
     * @param revocationRequest revocation request
     */
    @PostMapping(path = "/api/v1/revocations/revoke", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    void revoke(@RequestBody RevocationRequest revocationRequest);

    /**
     * Revoke VC.
     *
     * @param suspendRequest revocation request
     */
    @PostMapping(path = "/api/v1/revocations/suspend", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    void suspend(@RequestBody SuspendRequest suspendRequest);

    /**
     * Verify revocation/suspend status of VC
     *
     * @param statusVerificationRequest the status verification request
     * @return the status verification response
     */
    @PostMapping(path = "/api/v1/revocations/verify", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    StatusVerificationResponse verify(@RequestBody StatusVerificationRequest statusVerificationRequest);

    /**
     * Gets status list 2021 credential.
     *
     * @param credentialName the credential name
     * @return the status list 2021 credential
     */
    @GetMapping(path = "/api/v1/revocations/credentials/{credentialName}")
    Map<String, Object> getStatusList2021Credential(@PathVariable(name = "credentialName") String credentialName);
}