// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ApiGateway.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.ApiGateway.outputs.GetDeploymentSpecificationRequestPolicyAuthenticationValidationFailurePolicyResponseHeaderTransformationRenameHeaderItem;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetDeploymentSpecificationRequestPolicyAuthenticationValidationFailurePolicyResponseHeaderTransformationRenameHeader {
    /**
     * @return The list of headers.
     * 
     */
    private List<GetDeploymentSpecificationRequestPolicyAuthenticationValidationFailurePolicyResponseHeaderTransformationRenameHeaderItem> items;

    private GetDeploymentSpecificationRequestPolicyAuthenticationValidationFailurePolicyResponseHeaderTransformationRenameHeader() {}
    /**
     * @return The list of headers.
     * 
     */
    public List<GetDeploymentSpecificationRequestPolicyAuthenticationValidationFailurePolicyResponseHeaderTransformationRenameHeaderItem> items() {
        return this.items;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDeploymentSpecificationRequestPolicyAuthenticationValidationFailurePolicyResponseHeaderTransformationRenameHeader defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetDeploymentSpecificationRequestPolicyAuthenticationValidationFailurePolicyResponseHeaderTransformationRenameHeaderItem> items;
        public Builder() {}
        public Builder(GetDeploymentSpecificationRequestPolicyAuthenticationValidationFailurePolicyResponseHeaderTransformationRenameHeader defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
        }

        @CustomType.Setter
        public Builder items(List<GetDeploymentSpecificationRequestPolicyAuthenticationValidationFailurePolicyResponseHeaderTransformationRenameHeaderItem> items) {
            this.items = Objects.requireNonNull(items);
            return this;
        }
        public Builder items(GetDeploymentSpecificationRequestPolicyAuthenticationValidationFailurePolicyResponseHeaderTransformationRenameHeaderItem... items) {
            return items(List.of(items));
        }
        public GetDeploymentSpecificationRequestPolicyAuthenticationValidationFailurePolicyResponseHeaderTransformationRenameHeader build() {
            final var o = new GetDeploymentSpecificationRequestPolicyAuthenticationValidationFailurePolicyResponseHeaderTransformationRenameHeader();
            o.items = items;
            return o;
        }
    }
}