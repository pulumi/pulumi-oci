// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseMigration.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Integer;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class MigrationGoldenGateDetailsSettingsReplicat {
    /**
     * @return (Updatable) Number of threads used to read trail files (valid for Parallel Replicat)
     * 
     */
    private @Nullable Integer mapParallelism;
    /**
     * @return (Updatable) Defines the range in which the Replicat automatically adjusts its apply parallelism (valid for Parallel Replicat)
     * 
     */
    private @Nullable Integer maxApplyParallelism;
    /**
     * @return (Updatable) Defines the range in which the Replicat automatically adjusts its apply parallelism (valid for Parallel Replicat)
     * 
     */
    private @Nullable Integer minApplyParallelism;

    private MigrationGoldenGateDetailsSettingsReplicat() {}
    /**
     * @return (Updatable) Number of threads used to read trail files (valid for Parallel Replicat)
     * 
     */
    public Optional<Integer> mapParallelism() {
        return Optional.ofNullable(this.mapParallelism);
    }
    /**
     * @return (Updatable) Defines the range in which the Replicat automatically adjusts its apply parallelism (valid for Parallel Replicat)
     * 
     */
    public Optional<Integer> maxApplyParallelism() {
        return Optional.ofNullable(this.maxApplyParallelism);
    }
    /**
     * @return (Updatable) Defines the range in which the Replicat automatically adjusts its apply parallelism (valid for Parallel Replicat)
     * 
     */
    public Optional<Integer> minApplyParallelism() {
        return Optional.ofNullable(this.minApplyParallelism);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(MigrationGoldenGateDetailsSettingsReplicat defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable Integer mapParallelism;
        private @Nullable Integer maxApplyParallelism;
        private @Nullable Integer minApplyParallelism;
        public Builder() {}
        public Builder(MigrationGoldenGateDetailsSettingsReplicat defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.mapParallelism = defaults.mapParallelism;
    	      this.maxApplyParallelism = defaults.maxApplyParallelism;
    	      this.minApplyParallelism = defaults.minApplyParallelism;
        }

        @CustomType.Setter
        public Builder mapParallelism(@Nullable Integer mapParallelism) {
            this.mapParallelism = mapParallelism;
            return this;
        }
        @CustomType.Setter
        public Builder maxApplyParallelism(@Nullable Integer maxApplyParallelism) {
            this.maxApplyParallelism = maxApplyParallelism;
            return this;
        }
        @CustomType.Setter
        public Builder minApplyParallelism(@Nullable Integer minApplyParallelism) {
            this.minApplyParallelism = minApplyParallelism;
            return this;
        }
        public MigrationGoldenGateDetailsSettingsReplicat build() {
            final var o = new MigrationGoldenGateDetailsSettingsReplicat();
            o.mapParallelism = mapParallelism;
            o.maxApplyParallelism = maxApplyParallelism;
            o.minApplyParallelism = minApplyParallelism;
            return o;
        }
    }
}