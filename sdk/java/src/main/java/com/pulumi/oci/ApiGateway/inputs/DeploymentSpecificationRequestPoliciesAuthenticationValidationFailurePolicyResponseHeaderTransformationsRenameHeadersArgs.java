// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ApiGateway.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.ApiGateway.inputs.DeploymentSpecificationRequestPoliciesAuthenticationValidationFailurePolicyResponseHeaderTransformationsRenameHeadersItemArgs;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class DeploymentSpecificationRequestPoliciesAuthenticationValidationFailurePolicyResponseHeaderTransformationsRenameHeadersArgs extends com.pulumi.resources.ResourceArgs {

    public static final DeploymentSpecificationRequestPoliciesAuthenticationValidationFailurePolicyResponseHeaderTransformationsRenameHeadersArgs Empty = new DeploymentSpecificationRequestPoliciesAuthenticationValidationFailurePolicyResponseHeaderTransformationsRenameHeadersArgs();

    /**
     * (Updatable) The list of headers.
     * 
     */
    @Import(name="items")
    private @Nullable Output<List<DeploymentSpecificationRequestPoliciesAuthenticationValidationFailurePolicyResponseHeaderTransformationsRenameHeadersItemArgs>> items;

    /**
     * @return (Updatable) The list of headers.
     * 
     */
    public Optional<Output<List<DeploymentSpecificationRequestPoliciesAuthenticationValidationFailurePolicyResponseHeaderTransformationsRenameHeadersItemArgs>>> items() {
        return Optional.ofNullable(this.items);
    }

    private DeploymentSpecificationRequestPoliciesAuthenticationValidationFailurePolicyResponseHeaderTransformationsRenameHeadersArgs() {}

    private DeploymentSpecificationRequestPoliciesAuthenticationValidationFailurePolicyResponseHeaderTransformationsRenameHeadersArgs(DeploymentSpecificationRequestPoliciesAuthenticationValidationFailurePolicyResponseHeaderTransformationsRenameHeadersArgs $) {
        this.items = $.items;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(DeploymentSpecificationRequestPoliciesAuthenticationValidationFailurePolicyResponseHeaderTransformationsRenameHeadersArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private DeploymentSpecificationRequestPoliciesAuthenticationValidationFailurePolicyResponseHeaderTransformationsRenameHeadersArgs $;

        public Builder() {
            $ = new DeploymentSpecificationRequestPoliciesAuthenticationValidationFailurePolicyResponseHeaderTransformationsRenameHeadersArgs();
        }

        public Builder(DeploymentSpecificationRequestPoliciesAuthenticationValidationFailurePolicyResponseHeaderTransformationsRenameHeadersArgs defaults) {
            $ = new DeploymentSpecificationRequestPoliciesAuthenticationValidationFailurePolicyResponseHeaderTransformationsRenameHeadersArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param items (Updatable) The list of headers.
         * 
         * @return builder
         * 
         */
        public Builder items(@Nullable Output<List<DeploymentSpecificationRequestPoliciesAuthenticationValidationFailurePolicyResponseHeaderTransformationsRenameHeadersItemArgs>> items) {
            $.items = items;
            return this;
        }

        /**
         * @param items (Updatable) The list of headers.
         * 
         * @return builder
         * 
         */
        public Builder items(List<DeploymentSpecificationRequestPoliciesAuthenticationValidationFailurePolicyResponseHeaderTransformationsRenameHeadersItemArgs> items) {
            return items(Output.of(items));
        }

        /**
         * @param items (Updatable) The list of headers.
         * 
         * @return builder
         * 
         */
        public Builder items(DeploymentSpecificationRequestPoliciesAuthenticationValidationFailurePolicyResponseHeaderTransformationsRenameHeadersItemArgs... items) {
            return items(List.of(items));
        }

        public DeploymentSpecificationRequestPoliciesAuthenticationValidationFailurePolicyResponseHeaderTransformationsRenameHeadersArgs build() {
            return $;
        }
    }

}