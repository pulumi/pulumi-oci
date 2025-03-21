// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ApiGateway.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.ApiGateway.outputs.GetDeploymentSpecificationRequestPolicyDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationFailurePolicyResponseHeaderTransformationFilterHeader;
import com.pulumi.oci.ApiGateway.outputs.GetDeploymentSpecificationRequestPolicyDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationFailurePolicyResponseHeaderTransformationRenameHeader;
import com.pulumi.oci.ApiGateway.outputs.GetDeploymentSpecificationRequestPolicyDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationFailurePolicyResponseHeaderTransformationSetHeader;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetDeploymentSpecificationRequestPolicyDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationFailurePolicyResponseHeaderTransformation {
    /**
     * @return Filter HTTP headers as they pass through the gateway.  The gateway applies filters after other transformations, so any headers set or renamed must also be listed here when using an ALLOW type policy.
     * 
     */
    private List<GetDeploymentSpecificationRequestPolicyDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationFailurePolicyResponseHeaderTransformationFilterHeader> filterHeaders;
    /**
     * @return Rename HTTP headers as they pass through the gateway.
     * 
     */
    private List<GetDeploymentSpecificationRequestPolicyDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationFailurePolicyResponseHeaderTransformationRenameHeader> renameHeaders;
    /**
     * @return Set HTTP headers as they pass through the gateway.
     * 
     */
    private List<GetDeploymentSpecificationRequestPolicyDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationFailurePolicyResponseHeaderTransformationSetHeader> setHeaders;

    private GetDeploymentSpecificationRequestPolicyDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationFailurePolicyResponseHeaderTransformation() {}
    /**
     * @return Filter HTTP headers as they pass through the gateway.  The gateway applies filters after other transformations, so any headers set or renamed must also be listed here when using an ALLOW type policy.
     * 
     */
    public List<GetDeploymentSpecificationRequestPolicyDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationFailurePolicyResponseHeaderTransformationFilterHeader> filterHeaders() {
        return this.filterHeaders;
    }
    /**
     * @return Rename HTTP headers as they pass through the gateway.
     * 
     */
    public List<GetDeploymentSpecificationRequestPolicyDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationFailurePolicyResponseHeaderTransformationRenameHeader> renameHeaders() {
        return this.renameHeaders;
    }
    /**
     * @return Set HTTP headers as they pass through the gateway.
     * 
     */
    public List<GetDeploymentSpecificationRequestPolicyDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationFailurePolicyResponseHeaderTransformationSetHeader> setHeaders() {
        return this.setHeaders;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDeploymentSpecificationRequestPolicyDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationFailurePolicyResponseHeaderTransformation defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetDeploymentSpecificationRequestPolicyDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationFailurePolicyResponseHeaderTransformationFilterHeader> filterHeaders;
        private List<GetDeploymentSpecificationRequestPolicyDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationFailurePolicyResponseHeaderTransformationRenameHeader> renameHeaders;
        private List<GetDeploymentSpecificationRequestPolicyDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationFailurePolicyResponseHeaderTransformationSetHeader> setHeaders;
        public Builder() {}
        public Builder(GetDeploymentSpecificationRequestPolicyDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationFailurePolicyResponseHeaderTransformation defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.filterHeaders = defaults.filterHeaders;
    	      this.renameHeaders = defaults.renameHeaders;
    	      this.setHeaders = defaults.setHeaders;
        }

        @CustomType.Setter
        public Builder filterHeaders(List<GetDeploymentSpecificationRequestPolicyDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationFailurePolicyResponseHeaderTransformationFilterHeader> filterHeaders) {
            if (filterHeaders == null) {
              throw new MissingRequiredPropertyException("GetDeploymentSpecificationRequestPolicyDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationFailurePolicyResponseHeaderTransformation", "filterHeaders");
            }
            this.filterHeaders = filterHeaders;
            return this;
        }
        public Builder filterHeaders(GetDeploymentSpecificationRequestPolicyDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationFailurePolicyResponseHeaderTransformationFilterHeader... filterHeaders) {
            return filterHeaders(List.of(filterHeaders));
        }
        @CustomType.Setter
        public Builder renameHeaders(List<GetDeploymentSpecificationRequestPolicyDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationFailurePolicyResponseHeaderTransformationRenameHeader> renameHeaders) {
            if (renameHeaders == null) {
              throw new MissingRequiredPropertyException("GetDeploymentSpecificationRequestPolicyDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationFailurePolicyResponseHeaderTransformation", "renameHeaders");
            }
            this.renameHeaders = renameHeaders;
            return this;
        }
        public Builder renameHeaders(GetDeploymentSpecificationRequestPolicyDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationFailurePolicyResponseHeaderTransformationRenameHeader... renameHeaders) {
            return renameHeaders(List.of(renameHeaders));
        }
        @CustomType.Setter
        public Builder setHeaders(List<GetDeploymentSpecificationRequestPolicyDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationFailurePolicyResponseHeaderTransformationSetHeader> setHeaders) {
            if (setHeaders == null) {
              throw new MissingRequiredPropertyException("GetDeploymentSpecificationRequestPolicyDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationFailurePolicyResponseHeaderTransformation", "setHeaders");
            }
            this.setHeaders = setHeaders;
            return this;
        }
        public Builder setHeaders(GetDeploymentSpecificationRequestPolicyDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationFailurePolicyResponseHeaderTransformationSetHeader... setHeaders) {
            return setHeaders(List.of(setHeaders));
        }
        public GetDeploymentSpecificationRequestPolicyDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationFailurePolicyResponseHeaderTransformation build() {
            final var _resultValue = new GetDeploymentSpecificationRequestPolicyDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationFailurePolicyResponseHeaderTransformation();
            _resultValue.filterHeaders = filterHeaders;
            _resultValue.renameHeaders = renameHeaders;
            _resultValue.setHeaders = setHeaders;
            return _resultValue;
        }
    }
}
