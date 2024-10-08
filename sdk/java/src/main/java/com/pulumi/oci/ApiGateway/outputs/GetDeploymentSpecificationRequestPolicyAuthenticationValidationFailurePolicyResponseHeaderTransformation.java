// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ApiGateway.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.ApiGateway.outputs.GetDeploymentSpecificationRequestPolicyAuthenticationValidationFailurePolicyResponseHeaderTransformationFilterHeader;
import com.pulumi.oci.ApiGateway.outputs.GetDeploymentSpecificationRequestPolicyAuthenticationValidationFailurePolicyResponseHeaderTransformationRenameHeader;
import com.pulumi.oci.ApiGateway.outputs.GetDeploymentSpecificationRequestPolicyAuthenticationValidationFailurePolicyResponseHeaderTransformationSetHeader;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetDeploymentSpecificationRequestPolicyAuthenticationValidationFailurePolicyResponseHeaderTransformation {
    /**
     * @return Filter HTTP headers as they pass through the gateway.  The gateway applies filters after other transformations, so any headers set or renamed must also be listed here when using an ALLOW type policy.
     * 
     */
    private List<GetDeploymentSpecificationRequestPolicyAuthenticationValidationFailurePolicyResponseHeaderTransformationFilterHeader> filterHeaders;
    /**
     * @return Rename HTTP headers as they pass through the gateway.
     * 
     */
    private List<GetDeploymentSpecificationRequestPolicyAuthenticationValidationFailurePolicyResponseHeaderTransformationRenameHeader> renameHeaders;
    /**
     * @return Set HTTP headers as they pass through the gateway.
     * 
     */
    private List<GetDeploymentSpecificationRequestPolicyAuthenticationValidationFailurePolicyResponseHeaderTransformationSetHeader> setHeaders;

    private GetDeploymentSpecificationRequestPolicyAuthenticationValidationFailurePolicyResponseHeaderTransformation() {}
    /**
     * @return Filter HTTP headers as they pass through the gateway.  The gateway applies filters after other transformations, so any headers set or renamed must also be listed here when using an ALLOW type policy.
     * 
     */
    public List<GetDeploymentSpecificationRequestPolicyAuthenticationValidationFailurePolicyResponseHeaderTransformationFilterHeader> filterHeaders() {
        return this.filterHeaders;
    }
    /**
     * @return Rename HTTP headers as they pass through the gateway.
     * 
     */
    public List<GetDeploymentSpecificationRequestPolicyAuthenticationValidationFailurePolicyResponseHeaderTransformationRenameHeader> renameHeaders() {
        return this.renameHeaders;
    }
    /**
     * @return Set HTTP headers as they pass through the gateway.
     * 
     */
    public List<GetDeploymentSpecificationRequestPolicyAuthenticationValidationFailurePolicyResponseHeaderTransformationSetHeader> setHeaders() {
        return this.setHeaders;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDeploymentSpecificationRequestPolicyAuthenticationValidationFailurePolicyResponseHeaderTransformation defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetDeploymentSpecificationRequestPolicyAuthenticationValidationFailurePolicyResponseHeaderTransformationFilterHeader> filterHeaders;
        private List<GetDeploymentSpecificationRequestPolicyAuthenticationValidationFailurePolicyResponseHeaderTransformationRenameHeader> renameHeaders;
        private List<GetDeploymentSpecificationRequestPolicyAuthenticationValidationFailurePolicyResponseHeaderTransformationSetHeader> setHeaders;
        public Builder() {}
        public Builder(GetDeploymentSpecificationRequestPolicyAuthenticationValidationFailurePolicyResponseHeaderTransformation defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.filterHeaders = defaults.filterHeaders;
    	      this.renameHeaders = defaults.renameHeaders;
    	      this.setHeaders = defaults.setHeaders;
        }

        @CustomType.Setter
        public Builder filterHeaders(List<GetDeploymentSpecificationRequestPolicyAuthenticationValidationFailurePolicyResponseHeaderTransformationFilterHeader> filterHeaders) {
            if (filterHeaders == null) {
              throw new MissingRequiredPropertyException("GetDeploymentSpecificationRequestPolicyAuthenticationValidationFailurePolicyResponseHeaderTransformation", "filterHeaders");
            }
            this.filterHeaders = filterHeaders;
            return this;
        }
        public Builder filterHeaders(GetDeploymentSpecificationRequestPolicyAuthenticationValidationFailurePolicyResponseHeaderTransformationFilterHeader... filterHeaders) {
            return filterHeaders(List.of(filterHeaders));
        }
        @CustomType.Setter
        public Builder renameHeaders(List<GetDeploymentSpecificationRequestPolicyAuthenticationValidationFailurePolicyResponseHeaderTransformationRenameHeader> renameHeaders) {
            if (renameHeaders == null) {
              throw new MissingRequiredPropertyException("GetDeploymentSpecificationRequestPolicyAuthenticationValidationFailurePolicyResponseHeaderTransformation", "renameHeaders");
            }
            this.renameHeaders = renameHeaders;
            return this;
        }
        public Builder renameHeaders(GetDeploymentSpecificationRequestPolicyAuthenticationValidationFailurePolicyResponseHeaderTransformationRenameHeader... renameHeaders) {
            return renameHeaders(List.of(renameHeaders));
        }
        @CustomType.Setter
        public Builder setHeaders(List<GetDeploymentSpecificationRequestPolicyAuthenticationValidationFailurePolicyResponseHeaderTransformationSetHeader> setHeaders) {
            if (setHeaders == null) {
              throw new MissingRequiredPropertyException("GetDeploymentSpecificationRequestPolicyAuthenticationValidationFailurePolicyResponseHeaderTransformation", "setHeaders");
            }
            this.setHeaders = setHeaders;
            return this;
        }
        public Builder setHeaders(GetDeploymentSpecificationRequestPolicyAuthenticationValidationFailurePolicyResponseHeaderTransformationSetHeader... setHeaders) {
            return setHeaders(List.of(setHeaders));
        }
        public GetDeploymentSpecificationRequestPolicyAuthenticationValidationFailurePolicyResponseHeaderTransformation build() {
            final var _resultValue = new GetDeploymentSpecificationRequestPolicyAuthenticationValidationFailurePolicyResponseHeaderTransformation();
            _resultValue.filterHeaders = filterHeaders;
            _resultValue.renameHeaders = renameHeaders;
            _resultValue.setHeaders = setHeaders;
            return _resultValue;
        }
    }
}
