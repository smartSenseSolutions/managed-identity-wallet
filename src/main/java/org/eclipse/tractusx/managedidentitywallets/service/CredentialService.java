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
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.text.StringEscapeUtils;
import org.eclipse.tractusx.managedidentitywallets.config.MIWSettings;
import org.eclipse.tractusx.managedidentitywallets.constant.StringPool;
import org.eclipse.tractusx.managedidentitywallets.dao.entity.Wallet;
import org.eclipse.tractusx.managedidentitywallets.exception.BadDataException;
import org.eclipse.tractusx.managedidentitywallets.exception.CredentialValidationProblem;
import org.eclipse.tractusx.managedidentitywallets.exception.ForbiddenException;
import org.eclipse.tractusx.managedidentitywallets.revocation.service.RevocationService;
import org.eclipse.tractusx.managedidentitywallets.utils.Validate;
import org.eclipse.tractusx.ssi.lib.did.resolver.DidDocumentResolverRegistry;
import org.eclipse.tractusx.ssi.lib.did.resolver.DidDocumentResolverRegistryImpl;
import org.eclipse.tractusx.ssi.lib.did.web.DidWebDocumentResolver;
import org.eclipse.tractusx.ssi.lib.did.web.util.DidWebParser;
import org.eclipse.tractusx.ssi.lib.model.verifiable.credential.VerifiableCredential;
import org.eclipse.tractusx.ssi.lib.model.verifiable.credential.VerifiableCredentialStatusList2021Entry;
import org.eclipse.tractusx.ssi.lib.proof.LinkedDataProofValidation;
import org.eclipse.tractusx.ssi.lib.proof.SignatureType;
import org.springframework.stereotype.Service;

import java.net.http.HttpClient;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

@Service
@Slf4j
@RequiredArgsConstructor
public class CredentialService {

    public static final String ISSUER_WALLET_BPN_IS_NOT_MATCHING_WITH_REQUEST_BPN_FROM_TOKEN = "Issuer wallet BPN is not matching with request BPN(from token)";

    private final CommonService commonService;

    private final RevocationService revocationService;

    private final MIWSettings miwSettings;


    /**
     * Credentials validation map.
     *
     * @param verifiableCredential     the verifiableCredential
     * @param withCredentialExpiryDate the with credential expiry date
     * @param withRevocation           the with revocation
     * @return the map
     */
    public Map<String, Object> credentialsValidation(VerifiableCredential verifiableCredential, boolean withCredentialExpiryDate, boolean withRevocation) {

        // DID Resolver Constracture params
        DidDocumentResolverRegistry didDocumentResolverRegistry = new DidDocumentResolverRegistryImpl();
        didDocumentResolverRegistry.register(
                new DidWebDocumentResolver(HttpClient.newHttpClient(), new DidWebParser(), miwSettings.enforceHttps()));


        String proofTye = verifiableCredential.getProof().get(StringPool.TYPE).toString();
        LinkedDataProofValidation proofValidation;
        if (SignatureType.ED21559.toString().equals(proofTye)) {
            proofValidation = LinkedDataProofValidation.newInstance(
                    SignatureType.ED21559,
                    didDocumentResolverRegistry);
        } else if (SignatureType.JWS.toString().equals(proofTye)) {
            proofValidation = LinkedDataProofValidation.newInstance(
                    SignatureType.JWS,
                    didDocumentResolverRegistry);
        } else {
            throw new BadDataException(String.format("Invalid proof type: %s", proofTye));
        }

        boolean valid = proofValidation.verifiyProof(verifiableCredential);
        Map<String, Object> response = new TreeMap<>();

        //check expiry
        boolean dateValidation = CommonService.validateExpiry(withCredentialExpiryDate, verifiableCredential, response);

        //check revocation
        boolean isRevoked = commonService.validateRevocation(withRevocation, verifiableCredential, response);

        response.put(StringPool.VALID, valid && dateValidation && !isRevoked);
        response.put(StringPool.VC, verifiableCredential);

        return response;
    }

    /**
     * Credentials revoke.
     *
     * @param data      the data
     * @param callerBPN the caller bpn
     */
    public void revokeCredential(Map<String, Object> data, String callerBPN) {
        VerifiableCredential verifiableCredential = new VerifiableCredential(data);
        Validate.isNull(verifiableCredential.getVerifiableCredentialStatus()).launch(new BadDataException("Credential Status is not exists"));
        Wallet issuerWallet = commonService.getWalletByIdentifier(verifiableCredential.getIssuer().toString());

        //validate BPN access, Issuer must be caller of API
        Validate.isFalse(callerBPN.equals(issuerWallet.getBpn())).launch(new ForbiddenException(ISSUER_WALLET_BPN_IS_NOT_MATCHING_WITH_REQUEST_BPN_FROM_TOKEN));
        Map<String, Object> map = credentialsValidation(verifiableCredential, false, true);
        // validate vc
        if (!Boolean.parseBoolean(map.get(StringPool.VALID).toString())) {
            List<Map<String, Object>> validationResults = new ArrayList<>();
            map.put(StringPool.VC_ID, verifiableCredential.getId().toString());
            map.remove(StringPool.VC);
            validationResults.add(map);
            throw new CredentialValidationProblem(validationResults, "VC is invalid");
        }
        revocationService.revokeCredential((VerifiableCredentialStatusList2021Entry) verifiableCredential.getVerifiableCredentialStatus());
        log.debug("VC revoked with id ->{}", StringEscapeUtils.escapeJava(String.valueOf(verifiableCredential.getId())));
    }
}
