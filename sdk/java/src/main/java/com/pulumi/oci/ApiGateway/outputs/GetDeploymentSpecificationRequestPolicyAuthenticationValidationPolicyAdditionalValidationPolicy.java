// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ApiGateway.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.ApiGateway.outputs.GetDeploymentSpecificationRequestPolicyAuthenticationValidationPolicyAdditionalValidationPolicyVerifyClaim;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetDeploymentSpecificationRequestPolicyAuthenticationValidationPolicyAdditionalValidationPolicy {
    /**
     * @return The list of intended recipients for the token.
     * 
     */
    private List<String> audiences;
    /**
     * @return A list of parties that could have issued the token.
     * 
     */
    private List<String> issuers;
    /**
     * @return A list of claims which should be validated to consider the token valid.
     * 
     */
    private List<GetDeploymentSpecificationRequestPolicyAuthenticationValidationPolicyAdditionalValidationPolicyVerifyClaim> verifyClaims;

    private GetDeploymentSpecificationRequestPolicyAuthenticationValidationPolicyAdditionalValidationPolicy() {}
    /**
     * @return The list of intended recipients for the token.
     * 
     */
    public List<String> audiences() {
        return this.audiences;
    }
    /**
     * @return A list of parties that could have issued the token.
     * 
     */
    public List<String> issuers() {
        return this.issuers;
    }
    /**
     * @return A list of claims which should be validated to consider the token valid.
     * 
     */
    public List<GetDeploymentSpecificationRequestPolicyAuthenticationValidationPolicyAdditionalValidationPolicyVerifyClaim> verifyClaims() {
        return this.verifyClaims;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDeploymentSpecificationRequestPolicyAuthenticationValidationPolicyAdditionalValidationPolicy defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<String> audiences;
        private List<String> issuers;
        private List<GetDeploymentSpecificationRequestPolicyAuthenticationValidationPolicyAdditionalValidationPolicyVerifyClaim> verifyClaims;
        public Builder() {}
        public Builder(GetDeploymentSpecificationRequestPolicyAuthenticationValidationPolicyAdditionalValidationPolicy defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.audiences = defaults.audiences;
    	      this.issuers = defaults.issuers;
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
        public Builder issuers(List<String> issuers) {
            this.issuers = Objects.requireNonNull(issuers);
            return this;
        }
        public Builder issuers(String... issuers) {
            return issuers(List.of(issuers));
        }
        @CustomType.Setter
        public Builder verifyClaims(List<GetDeploymentSpecificationRequestPolicyAuthenticationValidationPolicyAdditionalValidationPolicyVerifyClaim> verifyClaims) {
            this.verifyClaims = Objects.requireNonNull(verifyClaims);
            return this;
        }
        public Builder verifyClaims(GetDeploymentSpecificationRequestPolicyAuthenticationValidationPolicyAdditionalValidationPolicyVerifyClaim... verifyClaims) {
            return verifyClaims(List.of(verifyClaims));
        }
        public GetDeploymentSpecificationRequestPolicyAuthenticationValidationPolicyAdditionalValidationPolicy build() {
            final var o = new GetDeploymentSpecificationRequestPolicyAuthenticationValidationPolicyAdditionalValidationPolicy();
            o.audiences = audiences;
            o.issuers = issuers;
            o.verifyClaims = verifyClaims;
            return o;
        }
    }
}