// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Integer;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class MaintenanceRunEstimatedPatchingTime {
    /**
     * @return The estimated time required in minutes for database server patching.
     * 
     */
    private final @Nullable Integer estimatedDbServerPatchingTime;
    /**
     * @return The estimated time required in minutes for network switch patching.
     * 
     */
    private final @Nullable Integer estimatedNetworkSwitchesPatchingTime;
    /**
     * @return The estimated time required in minutes for storage server patching.
     * 
     */
    private final @Nullable Integer estimatedStorageServerPatchingTime;
    /**
     * @return The estimated total time required in minutes for all patching operations.
     * 
     */
    private final @Nullable Integer totalEstimatedPatchingTime;

    @CustomType.Constructor
    private MaintenanceRunEstimatedPatchingTime(
        @CustomType.Parameter("estimatedDbServerPatchingTime") @Nullable Integer estimatedDbServerPatchingTime,
        @CustomType.Parameter("estimatedNetworkSwitchesPatchingTime") @Nullable Integer estimatedNetworkSwitchesPatchingTime,
        @CustomType.Parameter("estimatedStorageServerPatchingTime") @Nullable Integer estimatedStorageServerPatchingTime,
        @CustomType.Parameter("totalEstimatedPatchingTime") @Nullable Integer totalEstimatedPatchingTime) {
        this.estimatedDbServerPatchingTime = estimatedDbServerPatchingTime;
        this.estimatedNetworkSwitchesPatchingTime = estimatedNetworkSwitchesPatchingTime;
        this.estimatedStorageServerPatchingTime = estimatedStorageServerPatchingTime;
        this.totalEstimatedPatchingTime = totalEstimatedPatchingTime;
    }

    /**
     * @return The estimated time required in minutes for database server patching.
     * 
     */
    public Optional<Integer> estimatedDbServerPatchingTime() {
        return Optional.ofNullable(this.estimatedDbServerPatchingTime);
    }
    /**
     * @return The estimated time required in minutes for network switch patching.
     * 
     */
    public Optional<Integer> estimatedNetworkSwitchesPatchingTime() {
        return Optional.ofNullable(this.estimatedNetworkSwitchesPatchingTime);
    }
    /**
     * @return The estimated time required in minutes for storage server patching.
     * 
     */
    public Optional<Integer> estimatedStorageServerPatchingTime() {
        return Optional.ofNullable(this.estimatedStorageServerPatchingTime);
    }
    /**
     * @return The estimated total time required in minutes for all patching operations.
     * 
     */
    public Optional<Integer> totalEstimatedPatchingTime() {
        return Optional.ofNullable(this.totalEstimatedPatchingTime);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(MaintenanceRunEstimatedPatchingTime defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private @Nullable Integer estimatedDbServerPatchingTime;
        private @Nullable Integer estimatedNetworkSwitchesPatchingTime;
        private @Nullable Integer estimatedStorageServerPatchingTime;
        private @Nullable Integer totalEstimatedPatchingTime;

        public Builder() {
    	      // Empty
        }

        public Builder(MaintenanceRunEstimatedPatchingTime defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.estimatedDbServerPatchingTime = defaults.estimatedDbServerPatchingTime;
    	      this.estimatedNetworkSwitchesPatchingTime = defaults.estimatedNetworkSwitchesPatchingTime;
    	      this.estimatedStorageServerPatchingTime = defaults.estimatedStorageServerPatchingTime;
    	      this.totalEstimatedPatchingTime = defaults.totalEstimatedPatchingTime;
        }

        public Builder estimatedDbServerPatchingTime(@Nullable Integer estimatedDbServerPatchingTime) {
            this.estimatedDbServerPatchingTime = estimatedDbServerPatchingTime;
            return this;
        }
        public Builder estimatedNetworkSwitchesPatchingTime(@Nullable Integer estimatedNetworkSwitchesPatchingTime) {
            this.estimatedNetworkSwitchesPatchingTime = estimatedNetworkSwitchesPatchingTime;
            return this;
        }
        public Builder estimatedStorageServerPatchingTime(@Nullable Integer estimatedStorageServerPatchingTime) {
            this.estimatedStorageServerPatchingTime = estimatedStorageServerPatchingTime;
            return this;
        }
        public Builder totalEstimatedPatchingTime(@Nullable Integer totalEstimatedPatchingTime) {
            this.totalEstimatedPatchingTime = totalEstimatedPatchingTime;
            return this;
        }        public MaintenanceRunEstimatedPatchingTime build() {
            return new MaintenanceRunEstimatedPatchingTime(estimatedDbServerPatchingTime, estimatedNetworkSwitchesPatchingTime, estimatedStorageServerPatchingTime, totalEstimatedPatchingTime);
        }
    }
}
