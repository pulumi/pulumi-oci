// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ApiGateway.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.ApiGateway.outputs.GetApiDeploymentSpecificationRequestPolicyAuthentication;
import com.pulumi.oci.ApiGateway.outputs.GetApiDeploymentSpecificationRequestPolicyCor;
import com.pulumi.oci.ApiGateway.outputs.GetApiDeploymentSpecificationRequestPolicyMutualTl;
import com.pulumi.oci.ApiGateway.outputs.GetApiDeploymentSpecificationRequestPolicyRateLimiting;
import com.pulumi.oci.ApiGateway.outputs.GetApiDeploymentSpecificationRequestPolicyUsagePlan;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetApiDeploymentSpecificationRequestPolicy {
    /**
     * @return Information on how to authenticate incoming requests.
     * 
     */
    private List<GetApiDeploymentSpecificationRequestPolicyAuthentication> authentications;
    /**
     * @return Enable CORS (Cross-Origin-Resource-Sharing) request handling.
     * 
     */
    private List<GetApiDeploymentSpecificationRequestPolicyCor> cors;
    /**
     * @return Properties used to configure client mTLS verification when API Consumer makes connection to the gateway.
     * 
     */
    private List<GetApiDeploymentSpecificationRequestPolicyMutualTl> mutualTls;
    /**
     * @return Limit the number of requests that should be handled for the specified window using a specfic key.
     * 
     */
    private List<GetApiDeploymentSpecificationRequestPolicyRateLimiting> rateLimitings;
    /**
     * @return Usage plan policies for this deployment
     * 
     */
    private List<GetApiDeploymentSpecificationRequestPolicyUsagePlan> usagePlans;

    private GetApiDeploymentSpecificationRequestPolicy() {}
    /**
     * @return Information on how to authenticate incoming requests.
     * 
     */
    public List<GetApiDeploymentSpecificationRequestPolicyAuthentication> authentications() {
        return this.authentications;
    }
    /**
     * @return Enable CORS (Cross-Origin-Resource-Sharing) request handling.
     * 
     */
    public List<GetApiDeploymentSpecificationRequestPolicyCor> cors() {
        return this.cors;
    }
    /**
     * @return Properties used to configure client mTLS verification when API Consumer makes connection to the gateway.
     * 
     */
    public List<GetApiDeploymentSpecificationRequestPolicyMutualTl> mutualTls() {
        return this.mutualTls;
    }
    /**
     * @return Limit the number of requests that should be handled for the specified window using a specfic key.
     * 
     */
    public List<GetApiDeploymentSpecificationRequestPolicyRateLimiting> rateLimitings() {
        return this.rateLimitings;
    }
    /**
     * @return Usage plan policies for this deployment
     * 
     */
    public List<GetApiDeploymentSpecificationRequestPolicyUsagePlan> usagePlans() {
        return this.usagePlans;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetApiDeploymentSpecificationRequestPolicy defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetApiDeploymentSpecificationRequestPolicyAuthentication> authentications;
        private List<GetApiDeploymentSpecificationRequestPolicyCor> cors;
        private List<GetApiDeploymentSpecificationRequestPolicyMutualTl> mutualTls;
        private List<GetApiDeploymentSpecificationRequestPolicyRateLimiting> rateLimitings;
        private List<GetApiDeploymentSpecificationRequestPolicyUsagePlan> usagePlans;
        public Builder() {}
        public Builder(GetApiDeploymentSpecificationRequestPolicy defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.authentications = defaults.authentications;
    	      this.cors = defaults.cors;
    	      this.mutualTls = defaults.mutualTls;
    	      this.rateLimitings = defaults.rateLimitings;
    	      this.usagePlans = defaults.usagePlans;
        }

        @CustomType.Setter
        public Builder authentications(List<GetApiDeploymentSpecificationRequestPolicyAuthentication> authentications) {
            this.authentications = Objects.requireNonNull(authentications);
            return this;
        }
        public Builder authentications(GetApiDeploymentSpecificationRequestPolicyAuthentication... authentications) {
            return authentications(List.of(authentications));
        }
        @CustomType.Setter
        public Builder cors(List<GetApiDeploymentSpecificationRequestPolicyCor> cors) {
            this.cors = Objects.requireNonNull(cors);
            return this;
        }
        public Builder cors(GetApiDeploymentSpecificationRequestPolicyCor... cors) {
            return cors(List.of(cors));
        }
        @CustomType.Setter
        public Builder mutualTls(List<GetApiDeploymentSpecificationRequestPolicyMutualTl> mutualTls) {
            this.mutualTls = Objects.requireNonNull(mutualTls);
            return this;
        }
        public Builder mutualTls(GetApiDeploymentSpecificationRequestPolicyMutualTl... mutualTls) {
            return mutualTls(List.of(mutualTls));
        }
        @CustomType.Setter
        public Builder rateLimitings(List<GetApiDeploymentSpecificationRequestPolicyRateLimiting> rateLimitings) {
            this.rateLimitings = Objects.requireNonNull(rateLimitings);
            return this;
        }
        public Builder rateLimitings(GetApiDeploymentSpecificationRequestPolicyRateLimiting... rateLimitings) {
            return rateLimitings(List.of(rateLimitings));
        }
        @CustomType.Setter
        public Builder usagePlans(List<GetApiDeploymentSpecificationRequestPolicyUsagePlan> usagePlans) {
            this.usagePlans = Objects.requireNonNull(usagePlans);
            return this;
        }
        public Builder usagePlans(GetApiDeploymentSpecificationRequestPolicyUsagePlan... usagePlans) {
            return usagePlans(List.of(usagePlans));
        }
        public GetApiDeploymentSpecificationRequestPolicy build() {
            final var o = new GetApiDeploymentSpecificationRequestPolicy();
            o.authentications = authentications;
            o.cors = cors;
            o.mutualTls = mutualTls;
            o.rateLimitings = rateLimitings;
            o.usagePlans = usagePlans;
            return o;
        }
    }
}