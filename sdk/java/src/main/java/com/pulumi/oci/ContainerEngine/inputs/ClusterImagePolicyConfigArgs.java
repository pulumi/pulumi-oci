// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ContainerEngine.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.ContainerEngine.inputs.ClusterImagePolicyConfigKeyDetailArgs;
import java.lang.Boolean;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class ClusterImagePolicyConfigArgs extends com.pulumi.resources.ResourceArgs {

    public static final ClusterImagePolicyConfigArgs Empty = new ClusterImagePolicyConfigArgs();

    /**
     * (Updatable) Whether the image verification policy is enabled. Defaults to false. If set to true, the images will be verified against the policy at runtime.
     * 
     */
    @Import(name="isPolicyEnabled")
    private @Nullable Output<Boolean> isPolicyEnabled;

    /**
     * @return (Updatable) Whether the image verification policy is enabled. Defaults to false. If set to true, the images will be verified against the policy at runtime.
     * 
     */
    public Optional<Output<Boolean>> isPolicyEnabled() {
        return Optional.ofNullable(this.isPolicyEnabled);
    }

    /**
     * (Updatable) A list of KMS key details.
     * 
     */
    @Import(name="keyDetails")
    private @Nullable Output<List<ClusterImagePolicyConfigKeyDetailArgs>> keyDetails;

    /**
     * @return (Updatable) A list of KMS key details.
     * 
     */
    public Optional<Output<List<ClusterImagePolicyConfigKeyDetailArgs>>> keyDetails() {
        return Optional.ofNullable(this.keyDetails);
    }

    private ClusterImagePolicyConfigArgs() {}

    private ClusterImagePolicyConfigArgs(ClusterImagePolicyConfigArgs $) {
        this.isPolicyEnabled = $.isPolicyEnabled;
        this.keyDetails = $.keyDetails;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(ClusterImagePolicyConfigArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private ClusterImagePolicyConfigArgs $;

        public Builder() {
            $ = new ClusterImagePolicyConfigArgs();
        }

        public Builder(ClusterImagePolicyConfigArgs defaults) {
            $ = new ClusterImagePolicyConfigArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param isPolicyEnabled (Updatable) Whether the image verification policy is enabled. Defaults to false. If set to true, the images will be verified against the policy at runtime.
         * 
         * @return builder
         * 
         */
        public Builder isPolicyEnabled(@Nullable Output<Boolean> isPolicyEnabled) {
            $.isPolicyEnabled = isPolicyEnabled;
            return this;
        }

        /**
         * @param isPolicyEnabled (Updatable) Whether the image verification policy is enabled. Defaults to false. If set to true, the images will be verified against the policy at runtime.
         * 
         * @return builder
         * 
         */
        public Builder isPolicyEnabled(Boolean isPolicyEnabled) {
            return isPolicyEnabled(Output.of(isPolicyEnabled));
        }

        /**
         * @param keyDetails (Updatable) A list of KMS key details.
         * 
         * @return builder
         * 
         */
        public Builder keyDetails(@Nullable Output<List<ClusterImagePolicyConfigKeyDetailArgs>> keyDetails) {
            $.keyDetails = keyDetails;
            return this;
        }

        /**
         * @param keyDetails (Updatable) A list of KMS key details.
         * 
         * @return builder
         * 
         */
        public Builder keyDetails(List<ClusterImagePolicyConfigKeyDetailArgs> keyDetails) {
            return keyDetails(Output.of(keyDetails));
        }

        /**
         * @param keyDetails (Updatable) A list of KMS key details.
         * 
         * @return builder
         * 
         */
        public Builder keyDetails(ClusterImagePolicyConfigKeyDetailArgs... keyDetails) {
            return keyDetails(List.of(keyDetails));
        }

        public ClusterImagePolicyConfigArgs build() {
            return $;
        }
    }

}
