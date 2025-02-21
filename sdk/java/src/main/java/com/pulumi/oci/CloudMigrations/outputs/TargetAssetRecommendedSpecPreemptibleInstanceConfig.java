// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CloudMigrations.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.CloudMigrations.outputs.TargetAssetRecommendedSpecPreemptibleInstanceConfigPreemptionAction;
import java.util.List;
import java.util.Objects;
import javax.annotation.Nullable;

@CustomType
public final class TargetAssetRecommendedSpecPreemptibleInstanceConfig {
    /**
     * @return The action to run when the preemptible instance is interrupted for eviction.
     * 
     */
    private @Nullable List<TargetAssetRecommendedSpecPreemptibleInstanceConfigPreemptionAction> preemptionActions;

    private TargetAssetRecommendedSpecPreemptibleInstanceConfig() {}
    /**
     * @return The action to run when the preemptible instance is interrupted for eviction.
     * 
     */
    public List<TargetAssetRecommendedSpecPreemptibleInstanceConfigPreemptionAction> preemptionActions() {
        return this.preemptionActions == null ? List.of() : this.preemptionActions;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(TargetAssetRecommendedSpecPreemptibleInstanceConfig defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable List<TargetAssetRecommendedSpecPreemptibleInstanceConfigPreemptionAction> preemptionActions;
        public Builder() {}
        public Builder(TargetAssetRecommendedSpecPreemptibleInstanceConfig defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.preemptionActions = defaults.preemptionActions;
        }

        @CustomType.Setter
        public Builder preemptionActions(@Nullable List<TargetAssetRecommendedSpecPreemptibleInstanceConfigPreemptionAction> preemptionActions) {

            this.preemptionActions = preemptionActions;
            return this;
        }
        public Builder preemptionActions(TargetAssetRecommendedSpecPreemptibleInstanceConfigPreemptionAction... preemptionActions) {
            return preemptionActions(List.of(preemptionActions));
        }
        public TargetAssetRecommendedSpecPreemptibleInstanceConfig build() {
            final var _resultValue = new TargetAssetRecommendedSpecPreemptibleInstanceConfig();
            _resultValue.preemptionActions = preemptionActions;
            return _resultValue;
        }
    }
}
