// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ApiGateway.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.ApiGateway.outputs.DeploymentSpecificationRequestPoliciesDynamicAuthenticationAuthenticationServerAuthenticationServerDetail;
import com.pulumi.oci.ApiGateway.outputs.DeploymentSpecificationRequestPoliciesDynamicAuthenticationAuthenticationServerKey;
import java.util.Objects;

@CustomType
public final class DeploymentSpecificationRequestPoliciesDynamicAuthenticationAuthenticationServer {
    /**
     * @return (Updatable) Information on how to authenticate incoming requests.
     * 
     */
    private DeploymentSpecificationRequestPoliciesDynamicAuthenticationAuthenticationServerAuthenticationServerDetail authenticationServerDetail;
    /**
     * @return (Updatable) Information around the values for selector of an authentication/ routing branch.
     * 
     */
    private DeploymentSpecificationRequestPoliciesDynamicAuthenticationAuthenticationServerKey key;

    private DeploymentSpecificationRequestPoliciesDynamicAuthenticationAuthenticationServer() {}
    /**
     * @return (Updatable) Information on how to authenticate incoming requests.
     * 
     */
    public DeploymentSpecificationRequestPoliciesDynamicAuthenticationAuthenticationServerAuthenticationServerDetail authenticationServerDetail() {
        return this.authenticationServerDetail;
    }
    /**
     * @return (Updatable) Information around the values for selector of an authentication/ routing branch.
     * 
     */
    public DeploymentSpecificationRequestPoliciesDynamicAuthenticationAuthenticationServerKey key() {
        return this.key;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(DeploymentSpecificationRequestPoliciesDynamicAuthenticationAuthenticationServer defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private DeploymentSpecificationRequestPoliciesDynamicAuthenticationAuthenticationServerAuthenticationServerDetail authenticationServerDetail;
        private DeploymentSpecificationRequestPoliciesDynamicAuthenticationAuthenticationServerKey key;
        public Builder() {}
        public Builder(DeploymentSpecificationRequestPoliciesDynamicAuthenticationAuthenticationServer defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.authenticationServerDetail = defaults.authenticationServerDetail;
    	      this.key = defaults.key;
        }

        @CustomType.Setter
        public Builder authenticationServerDetail(DeploymentSpecificationRequestPoliciesDynamicAuthenticationAuthenticationServerAuthenticationServerDetail authenticationServerDetail) {
            this.authenticationServerDetail = Objects.requireNonNull(authenticationServerDetail);
            return this;
        }
        @CustomType.Setter
        public Builder key(DeploymentSpecificationRequestPoliciesDynamicAuthenticationAuthenticationServerKey key) {
            this.key = Objects.requireNonNull(key);
            return this;
        }
        public DeploymentSpecificationRequestPoliciesDynamicAuthenticationAuthenticationServer build() {
            final var o = new DeploymentSpecificationRequestPoliciesDynamicAuthenticationAuthenticationServer();
            o.authenticationServerDetail = authenticationServerDetail;
            o.key = key;
            return o;
        }
    }
}