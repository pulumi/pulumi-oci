// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseMigration.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DatabaseMigration.outputs.MigrationGoldenGateDetailsHub;
import com.pulumi.oci.DatabaseMigration.outputs.MigrationGoldenGateDetailsSettings;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class MigrationGoldenGateDetails {
    /**
     * @return (Updatable) Details about Oracle GoldenGate Microservices. Required for online logical migration.
     * 
     */
    private final MigrationGoldenGateDetailsHub hub;
    /**
     * @return (Updatable) Optional settings for GoldenGate Microservices processes
     * 
     */
    private final @Nullable MigrationGoldenGateDetailsSettings settings;

    @CustomType.Constructor
    private MigrationGoldenGateDetails(
        @CustomType.Parameter("hub") MigrationGoldenGateDetailsHub hub,
        @CustomType.Parameter("settings") @Nullable MigrationGoldenGateDetailsSettings settings) {
        this.hub = hub;
        this.settings = settings;
    }

    /**
     * @return (Updatable) Details about Oracle GoldenGate Microservices. Required for online logical migration.
     * 
     */
    public MigrationGoldenGateDetailsHub hub() {
        return this.hub;
    }
    /**
     * @return (Updatable) Optional settings for GoldenGate Microservices processes
     * 
     */
    public Optional<MigrationGoldenGateDetailsSettings> settings() {
        return Optional.ofNullable(this.settings);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(MigrationGoldenGateDetails defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private MigrationGoldenGateDetailsHub hub;
        private @Nullable MigrationGoldenGateDetailsSettings settings;

        public Builder() {
    	      // Empty
        }

        public Builder(MigrationGoldenGateDetails defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.hub = defaults.hub;
    	      this.settings = defaults.settings;
        }

        public Builder hub(MigrationGoldenGateDetailsHub hub) {
            this.hub = Objects.requireNonNull(hub);
            return this;
        }
        public Builder settings(@Nullable MigrationGoldenGateDetailsSettings settings) {
            this.settings = settings;
            return this;
        }        public MigrationGoldenGateDetails build() {
            return new MigrationGoldenGateDetails(hub, settings);
        }
    }
}
