// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ApiGateway.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.ApiGateway.outputs.GetDeploymentsDeploymentCollectionSpecificationRequestPolicyDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationFailurePolicyResponseHeaderTransformationFilterHeader;
import com.pulumi.oci.ApiGateway.outputs.GetDeploymentsDeploymentCollectionSpecificationRequestPolicyDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationFailurePolicyResponseHeaderTransformationRenameHeader;
import com.pulumi.oci.ApiGateway.outputs.GetDeploymentsDeploymentCollectionSpecificationRequestPolicyDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationFailurePolicyResponseHeaderTransformationSetHeader;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetDeploymentsDeploymentCollectionSpecificationRequestPolicyDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationFailurePolicyResponseHeaderTransformation {
    /**
     * @return Filter HTTP headers as they pass through the gateway.  The gateway applies filters after other transformations, so any headers set or renamed must also be listed here when using an ALLOW type policy.
     * 
     */
    private List<GetDeploymentsDeploymentCollectionSpecificationRequestPolicyDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationFailurePolicyResponseHeaderTransformationFilterHeader> filterHeaders;
    /**
     * @return Rename HTTP headers as they pass through the gateway.
     * 
     */
    private List<GetDeploymentsDeploymentCollectionSpecificationRequestPolicyDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationFailurePolicyResponseHeaderTransformationRenameHeader> renameHeaders;
    /**
     * @return Set HTTP headers as they pass through the gateway.
     * 
     */
    private List<GetDeploymentsDeploymentCollectionSpecificationRequestPolicyDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationFailurePolicyResponseHeaderTransformationSetHeader> setHeaders;

    private GetDeploymentsDeploymentCollectionSpecificationRequestPolicyDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationFailurePolicyResponseHeaderTransformation() {}
    /**
     * @return Filter HTTP headers as they pass through the gateway.  The gateway applies filters after other transformations, so any headers set or renamed must also be listed here when using an ALLOW type policy.
     * 
     */
    public List<GetDeploymentsDeploymentCollectionSpecificationRequestPolicyDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationFailurePolicyResponseHeaderTransformationFilterHeader> filterHeaders() {
        return this.filterHeaders;
    }
    /**
     * @return Rename HTTP headers as they pass through the gateway.
     * 
     */
    public List<GetDeploymentsDeploymentCollectionSpecificationRequestPolicyDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationFailurePolicyResponseHeaderTransformationRenameHeader> renameHeaders() {
        return this.renameHeaders;
    }
    /**
     * @return Set HTTP headers as they pass through the gateway.
     * 
     */
    public List<GetDeploymentsDeploymentCollectionSpecificationRequestPolicyDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationFailurePolicyResponseHeaderTransformationSetHeader> setHeaders() {
        return this.setHeaders;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDeploymentsDeploymentCollectionSpecificationRequestPolicyDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationFailurePolicyResponseHeaderTransformation defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetDeploymentsDeploymentCollectionSpecificationRequestPolicyDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationFailurePolicyResponseHeaderTransformationFilterHeader> filterHeaders;
        private List<GetDeploymentsDeploymentCollectionSpecificationRequestPolicyDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationFailurePolicyResponseHeaderTransformationRenameHeader> renameHeaders;
        private List<GetDeploymentsDeploymentCollectionSpecificationRequestPolicyDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationFailurePolicyResponseHeaderTransformationSetHeader> setHeaders;
        public Builder() {}
        public Builder(GetDeploymentsDeploymentCollectionSpecificationRequestPolicyDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationFailurePolicyResponseHeaderTransformation defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.filterHeaders = defaults.filterHeaders;
    	      this.renameHeaders = defaults.renameHeaders;
    	      this.setHeaders = defaults.setHeaders;
        }

        @CustomType.Setter
        public Builder filterHeaders(List<GetDeploymentsDeploymentCollectionSpecificationRequestPolicyDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationFailurePolicyResponseHeaderTransformationFilterHeader> filterHeaders) {
            this.filterHeaders = Objects.requireNonNull(filterHeaders);
            return this;
        }
        public Builder filterHeaders(GetDeploymentsDeploymentCollectionSpecificationRequestPolicyDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationFailurePolicyResponseHeaderTransformationFilterHeader... filterHeaders) {
            return filterHeaders(List.of(filterHeaders));
        }
        @CustomType.Setter
        public Builder renameHeaders(List<GetDeploymentsDeploymentCollectionSpecificationRequestPolicyDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationFailurePolicyResponseHeaderTransformationRenameHeader> renameHeaders) {
            this.renameHeaders = Objects.requireNonNull(renameHeaders);
            return this;
        }
        public Builder renameHeaders(GetDeploymentsDeploymentCollectionSpecificationRequestPolicyDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationFailurePolicyResponseHeaderTransformationRenameHeader... renameHeaders) {
            return renameHeaders(List.of(renameHeaders));
        }
        @CustomType.Setter
        public Builder setHeaders(List<GetDeploymentsDeploymentCollectionSpecificationRequestPolicyDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationFailurePolicyResponseHeaderTransformationSetHeader> setHeaders) {
            this.setHeaders = Objects.requireNonNull(setHeaders);
            return this;
        }
        public Builder setHeaders(GetDeploymentsDeploymentCollectionSpecificationRequestPolicyDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationFailurePolicyResponseHeaderTransformationSetHeader... setHeaders) {
            return setHeaders(List.of(setHeaders));
        }
        public GetDeploymentsDeploymentCollectionSpecificationRequestPolicyDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationFailurePolicyResponseHeaderTransformation build() {
            final var o = new GetDeploymentsDeploymentCollectionSpecificationRequestPolicyDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationFailurePolicyResponseHeaderTransformation();
            o.filterHeaders = filterHeaders;
            o.renameHeaders = renameHeaders;
            o.setHeaders = setHeaders;
            return o;
        }
    }
}