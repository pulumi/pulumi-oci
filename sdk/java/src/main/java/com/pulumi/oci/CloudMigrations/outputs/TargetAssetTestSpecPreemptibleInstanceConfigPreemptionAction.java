// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CloudMigrations.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Boolean;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class TargetAssetTestSpecPreemptibleInstanceConfigPreemptionAction {
    /**
     * @return (Updatable) Whether to preserve the boot volume that was used to launch the preemptible instance when the instance is terminated. By default, it is false if not specified.
     * 
     */
    private @Nullable Boolean preserveBootVolume;
    /**
     * @return (Updatable) The type of action to run when the instance is interrupted for eviction.
     * 
     */
    private @Nullable String type;

    private TargetAssetTestSpecPreemptibleInstanceConfigPreemptionAction() {}
    /**
     * @return (Updatable) Whether to preserve the boot volume that was used to launch the preemptible instance when the instance is terminated. By default, it is false if not specified.
     * 
     */
    public Optional<Boolean> preserveBootVolume() {
        return Optional.ofNullable(this.preserveBootVolume);
    }
    /**
     * @return (Updatable) The type of action to run when the instance is interrupted for eviction.
     * 
     */
    public Optional<String> type() {
        return Optional.ofNullable(this.type);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(TargetAssetTestSpecPreemptibleInstanceConfigPreemptionAction defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable Boolean preserveBootVolume;
        private @Nullable String type;
        public Builder() {}
        public Builder(TargetAssetTestSpecPreemptibleInstanceConfigPreemptionAction defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.preserveBootVolume = defaults.preserveBootVolume;
    	      this.type = defaults.type;
        }

        @CustomType.Setter
        public Builder preserveBootVolume(@Nullable Boolean preserveBootVolume) {
            this.preserveBootVolume = preserveBootVolume;
            return this;
        }
        @CustomType.Setter
        public Builder type(@Nullable String type) {
            this.type = type;
            return this;
        }
        public TargetAssetTestSpecPreemptibleInstanceConfigPreemptionAction build() {
            final var o = new TargetAssetTestSpecPreemptibleInstanceConfigPreemptionAction();
            o.preserveBootVolume = preserveBootVolume;
            o.type = type;
            return o;
        }
    }
}