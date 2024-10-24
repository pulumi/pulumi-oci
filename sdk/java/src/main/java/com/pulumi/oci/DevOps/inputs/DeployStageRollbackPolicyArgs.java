// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DevOps.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class DeployStageRollbackPolicyArgs extends com.pulumi.resources.ResourceArgs {

    public static final DeployStageRollbackPolicyArgs Empty = new DeployStageRollbackPolicyArgs();

    /**
     * (Updatable) Specifies type of the deployment stage rollback policy.
     * 
     */
    @Import(name="policyType")
    private @Nullable Output<String> policyType;

    /**
     * @return (Updatable) Specifies type of the deployment stage rollback policy.
     * 
     */
    public Optional<Output<String>> policyType() {
        return Optional.ofNullable(this.policyType);
    }

    private DeployStageRollbackPolicyArgs() {}

    private DeployStageRollbackPolicyArgs(DeployStageRollbackPolicyArgs $) {
        this.policyType = $.policyType;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(DeployStageRollbackPolicyArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private DeployStageRollbackPolicyArgs $;

        public Builder() {
            $ = new DeployStageRollbackPolicyArgs();
        }

        public Builder(DeployStageRollbackPolicyArgs defaults) {
            $ = new DeployStageRollbackPolicyArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param policyType (Updatable) Specifies type of the deployment stage rollback policy.
         * 
         * @return builder
         * 
         */
        public Builder policyType(@Nullable Output<String> policyType) {
            $.policyType = policyType;
            return this;
        }

        /**
         * @param policyType (Updatable) Specifies type of the deployment stage rollback policy.
         * 
         * @return builder
         * 
         */
        public Builder policyType(String policyType) {
            return policyType(Output.of(policyType));
        }

        public DeployStageRollbackPolicyArgs build() {
            return $;
        }
    }

}
