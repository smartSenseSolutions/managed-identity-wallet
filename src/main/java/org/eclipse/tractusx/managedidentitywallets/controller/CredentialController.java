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

package org.eclipse.tractusx.managedidentitywallets.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.eclipse.tractusx.managedidentitywallets.constant.RestURI;
import org.eclipse.tractusx.managedidentitywallets.service.CredentialService;
import org.eclipse.tractusx.ssi.lib.model.verifiable.credential.VerifiableCredential;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;
import java.util.Map;

/**
 * The type Credential controller.
 */
@RestController
@RequiredArgsConstructor
public class CredentialController extends BaseController {


    /**
     * The constant API_TAG_VERIFIABLE_CREDENTIAL_VALIDATION.
     */
    public static final String API_TAG_VERIFIABLE_CREDENTIAL_VALIDATION = "Verifiable Credential - Validation";
    /**
     * The constant API_TAG_VERIFIABLE_CREDENTIAL_REVOKE.
     */
    public static final String API_TAG_VERIFIABLE_CREDENTIAL_REVOKE = "Verifiable Credential - Revoke";

    private final CredentialService credentialService;

    /**
     * Credentials validation response entity.
     *
     * @param verifiableCredential     the verifiableCredential
     * @param withCredentialExpiryDate the with credential expiry date
     * @param withRevocation           the with revocation
     * @return the response entity
     */
    @Tag(name = API_TAG_VERIFIABLE_CREDENTIAL_VALIDATION)
    @ApiResponse(responseCode = "401", description = "The request could not be completed due to a failed authorization.", content = {@Content(examples = {})})
    @ApiResponse(responseCode = "403", description = "The request could not be completed due to a forbidden access", content = {@Content(examples = {})})
    @ApiResponse(responseCode = "500", description = "Any other internal server error", content = {@Content(examples = {
            @ExampleObject(name = "Internal server error", value = """
                    {
                      "type": "about:blank",
                      "title": "Error Title",
                      "status": 500,
                      "detail": "Error Details",
                      "instance": "API endpoint",
                      "properties": {
                        "timestamp": 1689762476720
                      }
                    }
                    """)
    })})
    @ApiResponse(responseCode = "200", description = "Validate Verifiable Credentials", content = {
            @Content(examples = {
                    @ExampleObject(name = "Verifiable Credentials without check expiry", value = """
                             {
                               "valid": true,
                               "vc": {
                                 "issuanceDate": "2023-07-19T09:11:34Z",
                                 "credentialSubject": [
                                   {
                                     "bpn": "BPNL000000000000",
                                     "id": "did:web:localhost:BPNL000000000000",
                                     "type": "BpnCredential"
                                   }
                                 ],
                                 "id": "did:web:localhost:BPNL000000000000#f73e3631-ba87-4a03-bea3-b28700056879",
                                 "proof": {
                                   "created": "2023-07-19T09:11:39Z",
                                   "jws": "eyJhbGciOiJFZERTQSJ9..fdn2qU85auOltdHDLdHI7sJVV1ZPdftpiXd_ndXN0dFgSDWiIrScdD03wtvKLq_H-shQWfh2RYeMmrlEzAhfDw",
                                   "proofPurpose": "proofPurpose",
                                   "type": "JsonWebSignature2020",
                                   "verificationMethod": "did:web:localhost:BPNL000000000000#"
                                 },
                                 "type": [
                                   "VerifiableCredential",
                                   "BpnCredential"
                                 ],
                                 "@context": [
                                   "https://www.w3.org/2018/credentials/v1",
                                   "https://catenax-ng.github.io/product-core-schemas/businessPartnerData.json",
                                   "https://w3id.org/security/suites/jws-2020/v1"
                                 ],
                                 "issuer": "did:web:localhost:BPNL000000000000",
                                 "expirationDate": "2024-12-31T18:30:00Z"
                               }
                             }
                            """),
                    @ExampleObject(name = "Verifiable Credentials with check expiry", value = """
                             {
                               "valid": true,
                               "validateExpiryDate": true,
                               "vc": {
                                 "issuanceDate": "2023-07-19T09:11:34Z",
                                 "credentialSubject": [
                                   {
                                     "bpn": "BPNL000000000000",
                                     "id": "did:web:localhost:BPNL000000000000",
                                     "type": "BpnCredential"
                                   }
                                 ],
                                 "id": "did:web:localhost:BPNL000000000000#f73e3631-ba87-4a03-bea3-b28700056879",
                                 "proof": {
                                   "created": "2023-07-19T09:11:39Z",
                                   "jws": "eyJhbGciOiJFZERTQSJ9..fdn2qU85auOltdHDLdHI7sJVV1ZPdftpiXd_ndXN0dFgSDWiIrScdD03wtvKLq_H-shQWfh2RYeMmrlEzAhfDw",
                                   "proofPurpose": "proofPurpose",
                                   "type": "JsonWebSignature2020",
                                   "verificationMethod": "did:web:localhost:BPNL000000000000#"
                                 },
                                 "type": [
                                   "VerifiableCredential",
                                   "BpnCredential"
                                 ],
                                 "@context": [
                                   "https://www.w3.org/2018/credentials/v1",
                                   "https://catenax-ng.github.io/product-core-schemas/businessPartnerData.json",
                                   "https://w3id.org/security/suites/jws-2020/v1"
                                 ],
                                 "issuer": "did:web:localhost:BPNL000000000000",
                                 "expirationDate": "2024-12-31T18:30:00Z"
                               }
                             }
                            """),
                    @ExampleObject(name = "Verifiable expired credentials with check expiry ", value = """
                             {
                               "valid": false,
                               "validateExpiryDate": false,
                               "vc": {
                                 "issuanceDate": "2023-07-19T09:11:34Z",
                                 "credentialSubject": [
                                   {
                                     "bpn": "BPNL000000000000",
                                     "id": "did:web:localhost:BPNL000000000000",
                                     "type": "BpnCredential"
                                   }
                                 ],
                                 "id": "did:web:localhost:BPNL000000000000#f73e3631-ba87-4a03-bea3-b28700056879",
                                 "proof": {
                                   "created": "2023-07-19T09:11:39Z",
                                   "jws": "eyJhbGciOiJFZERTQSJ9..fdn2qU85auOltdHDLdHI7sJVV1ZPdftpiXd_ndXN0dFgSDWiIrScdD03wtvKLq_H-shQWfh2RYeMmrlEzAhfDw",
                                   "proofPurpose": "proofPurpose",
                                   "type": "JsonWebSignature2020",
                                   "verificationMethod": "did:web:localhost:BPNL000000000000#"
                                 },
                                 "type": [
                                   "VerifiableCredential",
                                   "BpnCredential"
                                 ],
                                 "@context": [
                                   "https://www.w3.org/2018/credentials/v1",
                                   "https://catenax-ng.github.io/product-core-schemas/businessPartnerData.json",
                                   "https://w3id.org/security/suites/jws-2020/v1"
                                 ],
                                 "issuer": "did:web:localhost:BPNL000000000000",
                                 "expirationDate": "2022-12-31T18:30:00Z"
                               }
                             }
                            """),
                    @ExampleObject(name = "Verifiable Credentials with invalid signature", value = """
                             {
                               "valid": false,
                               "vc": {
                               "@context": [
                                   "https://www.w3.org/2018/credentials/v1",
                                   "https://catenax-ng.github.io/product-core-schemas/businessPartnerData.json",
                                   "https://w3id.org/security/suites/jws-2020/v1"
                                 ],
                                 "id": "did:web:localhost:BPNL000000000000#f73e3631-ba87-4a03-bea3-b28700056879",
                                 "type": [
                                   "VerifiableCredential",
                                   "BpnCredential"
                                 ],
                                 "issuer": "did:web:localhost:BPNL000000000000",
                                 "expirationDate": "2024-12-31T18:30:00Z"
                                 "issuanceDate": "2023-07-19T09:11:34Z",
                                 "credentialSubject": [
                                   {
                                     "bpn": "BPNL000000000000",
                                     "id": "did:web:localhost:BPNL000000000000",
                                     "type": "BpnCredential"
                                   }
                                 ],
                                 "proof": {
                                   "created": "2023-07-19T09:11:39Z",
                                   "jws": "eyJhbGciOiJFZERTQSJ9..fdn2qU85auOltdHDLdHI7sJVV1ZPdftpiXd_ndXN0dFgSDWiIrScdD03wtvKLq_H-shQWfh2RYeMmrlEzAhf",
                                   "proofPurpose": "proofPurpose",
                                   "type": "JsonWebSignature2020",
                                   "verificationMethod": "did:web:localhost:BPNL000000000000#"
                                 },
                               }
                             }
                            """)
            })
    })
    @Operation(summary = "Validate Verifiable Credentials", description = "Permission: **view_wallets** OR **view_wallet** \n\n Validate Verifiable Credentials")
    @PostMapping(path = RestURI.CREDENTIALS_VALIDATION, consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    @io.swagger.v3.oas.annotations.parameters.RequestBody(content = {
            @Content(examples = @ExampleObject("""
                                {
                                  "@context": [
                                    "https://www.w3.org/2018/credentials/v1",
                                    "https://catenax-ng.github.io/product-core-schemas/businessPartnerData.json",
                                    "https://w3id.org/security/suites/jws-2020/v1"
                                  ],
                                  "id": "did:web:localhost:BPNL000000000000#f73e3631-ba87-4a03-bea3-b28700056879",
                                  "type": [
                                    "VerifiableCredential",
                                    "BpnCredential"
                                  ],
                                  "issuer": "did:web:localhost:BPNL000000000000",
                                  "issuanceDate": "2023-07-19T09:11:34Z",
                                  "expirationDate": "2024-12-31T18:30:00Z",
                                  "credentialSubject": [
                                    {
                                      "bpn": "BPNL000000000000",
                                      "id": "did:web:localhost:BPNL000000000000",
                                      "type": "BpnCredential"
                                    }
                                  ],
                                  "proof": {
                                    "created": "2023-07-19T09:11:39Z",
                                    "jws": "eyJhbGciOiJFZERTQSJ9..fdn2qU85auOltdHDLdHI7sJVV1ZPdftpiXd_ndXN0dFgSDWiIrScdD03wtvKLq_H-shQWfh2RYeMmrlEzAhfDw",
                                    "proofPurpose": "proofPurpose",
                                    "type": "JsonWebSignature2020",
                                    "verificationMethod": "did:web:localhost:BPNL000000000000#"
                                  }
                                }
                    """))
    })
    public ResponseEntity<Map<String, Object>> credentialsValidation(@RequestBody VerifiableCredential verifiableCredential,
                                                                     @Parameter(description = "Check expiry of VC") @RequestParam(name = "withCredentialExpiryDate", defaultValue = "false", required = false) boolean withCredentialExpiryDate,
                                                                     @Parameter(description = "Check revocation status of VC") @RequestParam(name = "withRevocation", defaultValue = "false", required = false) boolean withRevocation) {
        return ResponseEntity.status(HttpStatus.OK).body(credentialService.credentialsValidation(verifiableCredential, withCredentialExpiryDate, withRevocation));
    }

    /**
     * Credentials revoke response entity.
     *
     * @param data      the data
     * @param principal the principal
     * @return the response entity
     */
    @Tag(name = API_TAG_VERIFIABLE_CREDENTIAL_REVOKE)
    @Operation(summary = "Revoke Verifiable Credentials", description = "Permission: **update_wallets** OR **update_wallet** (The BPN of the issuer of the Verifiable Credential must equal BPN of caller) \n\n Revoke Verifiable Credentials")
    @PostMapping(path = RestURI.CREDENTIALS_REVOKE, consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    @ApiResponse(responseCode = "401", description = "The request could not be completed due to a failed authorization.", content = {@Content(examples = {})})
    @ApiResponse(responseCode = "403", description = "The request could not be completed due to a forbidden access", content = {@Content(examples = {})})
    @ApiResponse(responseCode = "500", description = "Any other internal server error", content = {@Content(examples = {
            @ExampleObject(name = "Internal server error", value = """
                    {
                      "type": "about:blank",
                      "title": "Error Title",
                      "status": 500,
                      "detail": "Error Details",
                      "instance": "API endpoint",
                      "properties": {
                        "timestamp": 1689762476720
                      }
                    }
                    """)
    })})
    @ApiResponse(responseCode = "404", description = "Wallet not found with caller BPN", content = {@Content(examples = {
            @ExampleObject(name = "Wallet not found with caller BPN", value = """
                    {
                        "type": "about:blank",
                        "title": "Wallet not found for identifier did:web:localhost:BPNL0000000",
                        "status": 404,
                        "detail": "Wallet not found for identifier did:web:localhost:BPNL0000000",
                        "instance": "/api/wallets/did%3Aweb%3Alocalhost%3ABPNL0000000/credentials",
                        "properties": {
                          "timestamp": 1689765541959
                        }
                      }
                    """)
    })})
    @ApiResponse(responseCode = "400", description = "Credential Status is not exists", content = {@Content(examples = {
            @ExampleObject(name = "Credential Status is not exists", value = """
                    {
                      "type": "about:blank",
                      "title": "Credential Status is not exists",
                      "status": 400,
                      "detail": "Credential Status is not exists",
                      "instance": "/api/credentials/revoke",
                      "properties": {
                        "timestamp": 1691667139395
                      }
                    }
                    """),
            @ExampleObject(name = "Credential is already revoked", value = """
                    {
                      "type": "about:blank",
                      "title": "VC is invalid",
                      "status": 400,
                      "detail": "VC is invalid",
                      "instance": "/api/credentials/revoke",
                      "properties": {
                        "timestamp": 1691668509808,
                        "validationResults": [
                          {
                            "revoked": true,
                            "valid": false,
                            "validateExpiryDate": true,
                            "vcId": "did:web:localhost:BPNL000000000000#f4c8b44a-95fc-4978-a85f-867630d82ffd"
                          }
                        ]
                      }
                    }
                    """),
            @ExampleObject(name = "Credential signature invalid", value = """
                    {
                      "type": "about:blank",
                      "title": "VC is invalid",
                      "status": 400,
                      "detail": "VC is invalid",
                      "instance": "/api/credentials/revoke",
                      "properties": {
                        "timestamp": 1691668509808,
                        "validationResults": [
                          {
                            "revoked": false,
                            "valid": false,
                            "validateExpiryDate": true,
                            "vcId": "did:web:localhost:BPNL000000000000#f4c8b44a-95fc-4978-a85f-867630d82ffd"
                          }
                        ]
                      }
                    }
                    """),
            @ExampleObject(name = "Credential is expired", value = """
                    {
                      "type": "about:blank",
                      "title": "VC is invalid",
                      "status": 400,
                      "detail": "VC is invalid",
                      "instance": "/api/credentials/revoke",
                      "properties": {
                        "timestamp": 1691668584169,
                        "validationResults": [
                          {
                            "revoked": false,
                            "valid": false,
                            "validateExpiryDate": false,
                            "vcId": "did:web:localhost:BPNL000000000000#b06725e5-c811-40c6-a711-8b2c2cd39bda"
                          }
                        ]
                      }
                    }
                    """)
    })})
    @ApiResponse(responseCode = "200", description = "Credential revoked", content = {@Content(examples = {})})
    @io.swagger.v3.oas.annotations.parameters.RequestBody(content = {
            @Content(examples = @ExampleObject("""
                                {
                                  "@context": [
                                    "https://www.w3.org/2018/credentials/v1",
                                    "https://catenax-ng.github.io/product-core-schemas/businessPartnerData.json",
                                    "https://w3id.org/security/suites/jws-2020/v1",
                                    "https://w3id.org/vc/status-list/2021/v1"
                                  ],
                                  "id": "did:web:localhost:BPNL000000000000#13fead34-93c0-4d7e-8ddb-9dbb7756b72e",
                                  "type": [
                                    "VerifiableCredential",
                                    "BpnCredential"
                                  ],
                                  "issuer": "did:web:localhost:BPNL000000000000",
                                  "issuanceDate": "2023-08-08T06:48:20Z",
                                  "expirationDate": "2024-12-31T18:30:00Z",
                                  "credentialStatus": {
                                    "type": "StatusList2021Entry",
                                    "id": "http://localhost:8085/api/v1/revocations/credentials/did:web:localhost:BPNL000000000000-revocation#5",
                                    "statusPurpose": "revocation",
                                    "statusListIndex": "5",
                                    "statusListCredential": "http://localhost:8085/api/v1/revocations/credentials/did:web:localhost:BPNL000000000000-revocation"
                                  },
                                  "credentialSubject": [
                                    {
                                      "bpn": "BPNL000000000000",
                                      "id": "did:web:localhost:BPNL000000000000",
                                      "type": "BpnCredential"
                                    }
                                  ],
                                  "proof": {
                                    "proofPurpose": "proofPurpose",
                                    "verificationMethod": "did:web:localhost:BPNL000000000000#",
                                    "type": "JsonWebSignature2020",
                                    "created": "2023-08-08T06:48:25Z",
                                    "jws": "eyJhbGciOiJFZERTQSJ9..jQQ6tVD5vl11dc_fqTkLkBOzLugQsCQyyaH4S8dE1fgGS19BgXytm6PMs1gyXpyD2RopQISvY2P345rgXpgNCA"
                                  }
                                }
                    """))
    })
    public ResponseEntity<Void> credentialsRevoke(@RequestBody Map<String, Object> data, Principal principal) {
        credentialService.credentialsRevoke(data, getBPNFromToken(principal));
        return ResponseEntity.status(HttpStatus.OK).build();
    }
}
