// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseMigration.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class MigrationGoldenGateDetailsSettingsExtract {
    /**
     * @return (Updatable) Length of time (in seconds) that a transaction can be open before Extract generates a warning message that the transaction is long-running. If not specified, Extract will not generate a warning on long-running transactions.
     * 
     */
    private final @Nullable Integer longTransDuration;
    /**
     * @return (Updatable) Extract performance.
     * 
     */
    private final @Nullable String performanceProfile;

    @CustomType.Constructor
    private MigrationGoldenGateDetailsSettingsExtract(
        @CustomType.Parameter("longTransDuration") @Nullable Integer longTransDuration,
        @CustomType.Parameter("performanceProfile") @Nullable String performanceProfile) {
        this.longTransDuration = longTransDuration;
        this.performanceProfile = performanceProfile;
    }

    /**
     * @return (Updatable) Length of time (in seconds) that a transaction can be open before Extract generates a warning message that the transaction is long-running. If not specified, Extract will not generate a warning on long-running transactions.
     * 
     */
    public Optional<Integer> longTransDuration() {
        return Optional.ofNullable(this.longTransDuration);
    }
    /**
     * @return (Updatable) Extract performance.
     * 
     */
    public Optional<String> performanceProfile() {
        return Optional.ofNullable(this.performanceProfile);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(MigrationGoldenGateDetailsSettingsExtract defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private @Nullable Integer longTransDuration;
        private @Nullable String performanceProfile;

        public Builder() {
    	      // Empty
        }

        public Builder(MigrationGoldenGateDetailsSettingsExtract defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.longTransDuration = defaults.longTransDuration;
    	      this.performanceProfile = defaults.performanceProfile;
        }

        public Builder longTransDuration(@Nullable Integer longTransDuration) {
            this.longTransDuration = longTransDuration;
            return this;
        }
        public Builder performanceProfile(@Nullable String performanceProfile) {
            this.performanceProfile = performanceProfile;
            return this;
        }        public MigrationGoldenGateDetailsSettingsExtract build() {
            return new MigrationGoldenGateDetailsSettingsExtract(longTransDuration, performanceProfile);
        }
    }
}
