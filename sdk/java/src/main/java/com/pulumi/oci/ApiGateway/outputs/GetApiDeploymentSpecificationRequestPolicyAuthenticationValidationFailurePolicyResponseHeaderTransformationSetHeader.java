// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ApiGateway.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.ApiGateway.outputs.GetApiDeploymentSpecificationRequestPolicyAuthenticationValidationFailurePolicyResponseHeaderTransformationSetHeaderItem;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetApiDeploymentSpecificationRequestPolicyAuthenticationValidationFailurePolicyResponseHeaderTransformationSetHeader {
    /**
     * @return The list of headers.
     * 
     */
    private List<GetApiDeploymentSpecificationRequestPolicyAuthenticationValidationFailurePolicyResponseHeaderTransformationSetHeaderItem> items;

    private GetApiDeploymentSpecificationRequestPolicyAuthenticationValidationFailurePolicyResponseHeaderTransformationSetHeader() {}
    /**
     * @return The list of headers.
     * 
     */
    public List<GetApiDeploymentSpecificationRequestPolicyAuthenticationValidationFailurePolicyResponseHeaderTransformationSetHeaderItem> items() {
        return this.items;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetApiDeploymentSpecificationRequestPolicyAuthenticationValidationFailurePolicyResponseHeaderTransformationSetHeader defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetApiDeploymentSpecificationRequestPolicyAuthenticationValidationFailurePolicyResponseHeaderTransformationSetHeaderItem> items;
        public Builder() {}
        public Builder(GetApiDeploymentSpecificationRequestPolicyAuthenticationValidationFailurePolicyResponseHeaderTransformationSetHeader defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
        }

        @CustomType.Setter
        public Builder items(List<GetApiDeploymentSpecificationRequestPolicyAuthenticationValidationFailurePolicyResponseHeaderTransformationSetHeaderItem> items) {
            if (items == null) {
              throw new MissingRequiredPropertyException("GetApiDeploymentSpecificationRequestPolicyAuthenticationValidationFailurePolicyResponseHeaderTransformationSetHeader", "items");
            }
            this.items = items;
            return this;
        }
        public Builder items(GetApiDeploymentSpecificationRequestPolicyAuthenticationValidationFailurePolicyResponseHeaderTransformationSetHeaderItem... items) {
            return items(List.of(items));
        }
        public GetApiDeploymentSpecificationRequestPolicyAuthenticationValidationFailurePolicyResponseHeaderTransformationSetHeader build() {
            final var _resultValue = new GetApiDeploymentSpecificationRequestPolicyAuthenticationValidationFailurePolicyResponseHeaderTransformationSetHeader();
            _resultValue.items = items;
            return _resultValue;
        }
    }
}
