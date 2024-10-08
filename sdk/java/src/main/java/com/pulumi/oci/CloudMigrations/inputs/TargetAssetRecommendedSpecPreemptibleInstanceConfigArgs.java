// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CloudMigrations.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.CloudMigrations.inputs.TargetAssetRecommendedSpecPreemptibleInstanceConfigPreemptionActionArgs;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class TargetAssetRecommendedSpecPreemptibleInstanceConfigArgs extends com.pulumi.resources.ResourceArgs {

    public static final TargetAssetRecommendedSpecPreemptibleInstanceConfigArgs Empty = new TargetAssetRecommendedSpecPreemptibleInstanceConfigArgs();

    /**
     * The action to run when the preemptible instance is interrupted for eviction.
     * 
     */
    @Import(name="preemptionActions")
    private @Nullable Output<List<TargetAssetRecommendedSpecPreemptibleInstanceConfigPreemptionActionArgs>> preemptionActions;

    /**
     * @return The action to run when the preemptible instance is interrupted for eviction.
     * 
     */
    public Optional<Output<List<TargetAssetRecommendedSpecPreemptibleInstanceConfigPreemptionActionArgs>>> preemptionActions() {
        return Optional.ofNullable(this.preemptionActions);
    }

    private TargetAssetRecommendedSpecPreemptibleInstanceConfigArgs() {}

    private TargetAssetRecommendedSpecPreemptibleInstanceConfigArgs(TargetAssetRecommendedSpecPreemptibleInstanceConfigArgs $) {
        this.preemptionActions = $.preemptionActions;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(TargetAssetRecommendedSpecPreemptibleInstanceConfigArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private TargetAssetRecommendedSpecPreemptibleInstanceConfigArgs $;

        public Builder() {
            $ = new TargetAssetRecommendedSpecPreemptibleInstanceConfigArgs();
        }

        public Builder(TargetAssetRecommendedSpecPreemptibleInstanceConfigArgs defaults) {
            $ = new TargetAssetRecommendedSpecPreemptibleInstanceConfigArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param preemptionActions The action to run when the preemptible instance is interrupted for eviction.
         * 
         * @return builder
         * 
         */
        public Builder preemptionActions(@Nullable Output<List<TargetAssetRecommendedSpecPreemptibleInstanceConfigPreemptionActionArgs>> preemptionActions) {
            $.preemptionActions = preemptionActions;
            return this;
        }

        /**
         * @param preemptionActions The action to run when the preemptible instance is interrupted for eviction.
         * 
         * @return builder
         * 
         */
        public Builder preemptionActions(List<TargetAssetRecommendedSpecPreemptibleInstanceConfigPreemptionActionArgs> preemptionActions) {
            return preemptionActions(Output.of(preemptionActions));
        }

        /**
         * @param preemptionActions The action to run when the preemptible instance is interrupted for eviction.
         * 
         * @return builder
         * 
         */
        public Builder preemptionActions(TargetAssetRecommendedSpecPreemptibleInstanceConfigPreemptionActionArgs... preemptionActions) {
            return preemptionActions(List.of(preemptionActions));
        }

        public TargetAssetRecommendedSpecPreemptibleInstanceConfigArgs build() {
            return $;
        }
    }

}
