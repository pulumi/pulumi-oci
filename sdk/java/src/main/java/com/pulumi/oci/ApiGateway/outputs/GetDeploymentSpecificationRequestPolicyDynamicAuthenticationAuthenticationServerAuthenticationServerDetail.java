// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ApiGateway.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.ApiGateway.outputs.GetDeploymentSpecificationRequestPolicyDynamicAuthenticationAuthenticationServerAuthenticationServerDetailPublicKey;
import com.pulumi.oci.ApiGateway.outputs.GetDeploymentSpecificationRequestPolicyDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationFailurePolicy;
import com.pulumi.oci.ApiGateway.outputs.GetDeploymentSpecificationRequestPolicyDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationPolicy;
import com.pulumi.oci.ApiGateway.outputs.GetDeploymentSpecificationRequestPolicyDynamicAuthenticationAuthenticationServerAuthenticationServerDetailVerifyClaim;
import java.lang.Boolean;
import java.lang.Double;
import java.lang.Object;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetDeploymentSpecificationRequestPolicyDynamicAuthenticationAuthenticationServerAuthenticationServerDetail {
    /**
     * @return The list of intended recipients for the token.
     * 
     */
    private List<String> audiences;
    /**
     * @return A list of keys from &#34;parameters&#34; attribute value whose values will be added to the cache key.
     * 
     */
    private List<String> cacheKeys;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Oracle Functions function resource.
     * 
     */
    private String functionId;
    /**
     * @return Whether an unauthenticated user may access the API. Must be &#34;true&#34; to enable ANONYMOUS route authorization.
     * 
     */
    private Boolean isAnonymousAccessAllowed;
    /**
     * @return A list of parties that could have issued the token.
     * 
     */
    private List<String> issuers;
    /**
     * @return The maximum expected time difference between the system clocks of the token issuer and the API Gateway.
     * 
     */
    private Double maxClockSkewInSeconds;
    private Map<String,Object> parameters;
    /**
     * @return A set of Public Keys that will be used to verify the JWT signature.
     * 
     */
    private List<GetDeploymentSpecificationRequestPolicyDynamicAuthenticationAuthenticationServerAuthenticationServerDetailPublicKey> publicKeys;
    /**
     * @return The authentication scheme that is to be used when authenticating the token. This must to be provided if &#34;tokenHeader&#34; is specified.
     * 
     */
    private String tokenAuthScheme;
    /**
     * @return The name of the header containing the authentication token.
     * 
     */
    private String tokenHeader;
    /**
     * @return The name of the query parameter containing the authentication token.
     * 
     */
    private String tokenQueryParam;
    /**
     * @return Type of the Response Cache Store Policy.
     * 
     */
    private String type;
    /**
     * @return Policy for defining behaviour on validation failure.
     * 
     */
    private List<GetDeploymentSpecificationRequestPolicyDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationFailurePolicy> validationFailurePolicies;
    /**
     * @return Authentication Policies for the Token Authentication types.
     * 
     */
    private List<GetDeploymentSpecificationRequestPolicyDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationPolicy> validationPolicies;
    /**
     * @return A list of claims which should be validated to consider the token valid.
     * 
     */
    private List<GetDeploymentSpecificationRequestPolicyDynamicAuthenticationAuthenticationServerAuthenticationServerDetailVerifyClaim> verifyClaims;

    private GetDeploymentSpecificationRequestPolicyDynamicAuthenticationAuthenticationServerAuthenticationServerDetail() {}
    /**
     * @return The list of intended recipients for the token.
     * 
     */
    public List<String> audiences() {
        return this.audiences;
    }
    /**
     * @return A list of keys from &#34;parameters&#34; attribute value whose values will be added to the cache key.
     * 
     */
    public List<String> cacheKeys() {
        return this.cacheKeys;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Oracle Functions function resource.
     * 
     */
    public String functionId() {
        return this.functionId;
    }
    /**
     * @return Whether an unauthenticated user may access the API. Must be &#34;true&#34; to enable ANONYMOUS route authorization.
     * 
     */
    public Boolean isAnonymousAccessAllowed() {
        return this.isAnonymousAccessAllowed;
    }
    /**
     * @return A list of parties that could have issued the token.
     * 
     */
    public List<String> issuers() {
        return this.issuers;
    }
    /**
     * @return The maximum expected time difference between the system clocks of the token issuer and the API Gateway.
     * 
     */
    public Double maxClockSkewInSeconds() {
        return this.maxClockSkewInSeconds;
    }
    public Map<String,Object> parameters() {
        return this.parameters;
    }
    /**
     * @return A set of Public Keys that will be used to verify the JWT signature.
     * 
     */
    public List<GetDeploymentSpecificationRequestPolicyDynamicAuthenticationAuthenticationServerAuthenticationServerDetailPublicKey> publicKeys() {
        return this.publicKeys;
    }
    /**
     * @return The authentication scheme that is to be used when authenticating the token. This must to be provided if &#34;tokenHeader&#34; is specified.
     * 
     */
    public String tokenAuthScheme() {
        return this.tokenAuthScheme;
    }
    /**
     * @return The name of the header containing the authentication token.
     * 
     */
    public String tokenHeader() {
        return this.tokenHeader;
    }
    /**
     * @return The name of the query parameter containing the authentication token.
     * 
     */
    public String tokenQueryParam() {
        return this.tokenQueryParam;
    }
    /**
     * @return Type of the Response Cache Store Policy.
     * 
     */
    public String type() {
        return this.type;
    }
    /**
     * @return Policy for defining behaviour on validation failure.
     * 
     */
    public List<GetDeploymentSpecificationRequestPolicyDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationFailurePolicy> validationFailurePolicies() {
        return this.validationFailurePolicies;
    }
    /**
     * @return Authentication Policies for the Token Authentication types.
     * 
     */
    public List<GetDeploymentSpecificationRequestPolicyDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationPolicy> validationPolicies() {
        return this.validationPolicies;
    }
    /**
     * @return A list of claims which should be validated to consider the token valid.
     * 
     */
    public List<GetDeploymentSpecificationRequestPolicyDynamicAuthenticationAuthenticationServerAuthenticationServerDetailVerifyClaim> verifyClaims() {
        return this.verifyClaims;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDeploymentSpecificationRequestPolicyDynamicAuthenticationAuthenticationServerAuthenticationServerDetail defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<String> audiences;
        private List<String> cacheKeys;
        private String functionId;
        private Boolean isAnonymousAccessAllowed;
        private List<String> issuers;
        private Double maxClockSkewInSeconds;
        private Map<String,Object> parameters;
        private List<GetDeploymentSpecificationRequestPolicyDynamicAuthenticationAuthenticationServerAuthenticationServerDetailPublicKey> publicKeys;
        private String tokenAuthScheme;
        private String tokenHeader;
        private String tokenQueryParam;
        private String type;
        private List<GetDeploymentSpecificationRequestPolicyDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationFailurePolicy> validationFailurePolicies;
        private List<GetDeploymentSpecificationRequestPolicyDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationPolicy> validationPolicies;
        private List<GetDeploymentSpecificationRequestPolicyDynamicAuthenticationAuthenticationServerAuthenticationServerDetailVerifyClaim> verifyClaims;
        public Builder() {}
        public Builder(GetDeploymentSpecificationRequestPolicyDynamicAuthenticationAuthenticationServerAuthenticationServerDetail defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.audiences = defaults.audiences;
    	      this.cacheKeys = defaults.cacheKeys;
    	      this.functionId = defaults.functionId;
    	      this.isAnonymousAccessAllowed = defaults.isAnonymousAccessAllowed;
    	      this.issuers = defaults.issuers;
    	      this.maxClockSkewInSeconds = defaults.maxClockSkewInSeconds;
    	      this.parameters = defaults.parameters;
    	      this.publicKeys = defaults.publicKeys;
    	      this.tokenAuthScheme = defaults.tokenAuthScheme;
    	      this.tokenHeader = defaults.tokenHeader;
    	      this.tokenQueryParam = defaults.tokenQueryParam;
    	      this.type = defaults.type;
    	      this.validationFailurePolicies = defaults.validationFailurePolicies;
    	      this.validationPolicies = defaults.validationPolicies;
    	      this.verifyClaims = defaults.verifyClaims;
        }

        @CustomType.Setter
        public Builder audiences(List<String> audiences) {
            this.audiences = Objects.requireNonNull(audiences);
            return this;
        }
        public Builder audiences(String... audiences) {
            return audiences(List.of(audiences));
        }
        @CustomType.Setter
        public Builder cacheKeys(List<String> cacheKeys) {
            this.cacheKeys = Objects.requireNonNull(cacheKeys);
            return this;
        }
        public Builder cacheKeys(String... cacheKeys) {
            return cacheKeys(List.of(cacheKeys));
        }
        @CustomType.Setter
        public Builder functionId(String functionId) {
            this.functionId = Objects.requireNonNull(functionId);
            return this;
        }
        @CustomType.Setter
        public Builder isAnonymousAccessAllowed(Boolean isAnonymousAccessAllowed) {
            this.isAnonymousAccessAllowed = Objects.requireNonNull(isAnonymousAccessAllowed);
            return this;
        }
        @CustomType.Setter
        public Builder issuers(List<String> issuers) {
            this.issuers = Objects.requireNonNull(issuers);
            return this;
        }
        public Builder issuers(String... issuers) {
            return issuers(List.of(issuers));
        }
        @CustomType.Setter
        public Builder maxClockSkewInSeconds(Double maxClockSkewInSeconds) {
            this.maxClockSkewInSeconds = Objects.requireNonNull(maxClockSkewInSeconds);
            return this;
        }
        @CustomType.Setter
        public Builder parameters(Map<String,Object> parameters) {
            this.parameters = Objects.requireNonNull(parameters);
            return this;
        }
        @CustomType.Setter
        public Builder publicKeys(List<GetDeploymentSpecificationRequestPolicyDynamicAuthenticationAuthenticationServerAuthenticationServerDetailPublicKey> publicKeys) {
            this.publicKeys = Objects.requireNonNull(publicKeys);
            return this;
        }
        public Builder publicKeys(GetDeploymentSpecificationRequestPolicyDynamicAuthenticationAuthenticationServerAuthenticationServerDetailPublicKey... publicKeys) {
            return publicKeys(List.of(publicKeys));
        }
        @CustomType.Setter
        public Builder tokenAuthScheme(String tokenAuthScheme) {
            this.tokenAuthScheme = Objects.requireNonNull(tokenAuthScheme);
            return this;
        }
        @CustomType.Setter
        public Builder tokenHeader(String tokenHeader) {
            this.tokenHeader = Objects.requireNonNull(tokenHeader);
            return this;
        }
        @CustomType.Setter
        public Builder tokenQueryParam(String tokenQueryParam) {
            this.tokenQueryParam = Objects.requireNonNull(tokenQueryParam);
            return this;
        }
        @CustomType.Setter
        public Builder type(String type) {
            this.type = Objects.requireNonNull(type);
            return this;
        }
        @CustomType.Setter
        public Builder validationFailurePolicies(List<GetDeploymentSpecificationRequestPolicyDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationFailurePolicy> validationFailurePolicies) {
            this.validationFailurePolicies = Objects.requireNonNull(validationFailurePolicies);
            return this;
        }
        public Builder validationFailurePolicies(GetDeploymentSpecificationRequestPolicyDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationFailurePolicy... validationFailurePolicies) {
            return validationFailurePolicies(List.of(validationFailurePolicies));
        }
        @CustomType.Setter
        public Builder validationPolicies(List<GetDeploymentSpecificationRequestPolicyDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationPolicy> validationPolicies) {
            this.validationPolicies = Objects.requireNonNull(validationPolicies);
            return this;
        }
        public Builder validationPolicies(GetDeploymentSpecificationRequestPolicyDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationPolicy... validationPolicies) {
            return validationPolicies(List.of(validationPolicies));
        }
        @CustomType.Setter
        public Builder verifyClaims(List<GetDeploymentSpecificationRequestPolicyDynamicAuthenticationAuthenticationServerAuthenticationServerDetailVerifyClaim> verifyClaims) {
            this.verifyClaims = Objects.requireNonNull(verifyClaims);
            return this;
        }
        public Builder verifyClaims(GetDeploymentSpecificationRequestPolicyDynamicAuthenticationAuthenticationServerAuthenticationServerDetailVerifyClaim... verifyClaims) {
            return verifyClaims(List.of(verifyClaims));
        }
        public GetDeploymentSpecificationRequestPolicyDynamicAuthenticationAuthenticationServerAuthenticationServerDetail build() {
            final var o = new GetDeploymentSpecificationRequestPolicyDynamicAuthenticationAuthenticationServerAuthenticationServerDetail();
            o.audiences = audiences;
            o.cacheKeys = cacheKeys;
            o.functionId = functionId;
            o.isAnonymousAccessAllowed = isAnonymousAccessAllowed;
            o.issuers = issuers;
            o.maxClockSkewInSeconds = maxClockSkewInSeconds;
            o.parameters = parameters;
            o.publicKeys = publicKeys;
            o.tokenAuthScheme = tokenAuthScheme;
            o.tokenHeader = tokenHeader;
            o.tokenQueryParam = tokenQueryParam;
            o.type = type;
            o.validationFailurePolicies = validationFailurePolicies;
            o.validationPolicies = validationPolicies;
            o.verifyClaims = verifyClaims;
            return o;
        }
    }
}