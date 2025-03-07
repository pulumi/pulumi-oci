// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CloudMigrations.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Double;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class MigrationPlanStrategy {
    /**
     * @return (Updatable) The real resource usage is multiplied to this number before making any recommendation.
     * 
     */
    private @Nullable Double adjustmentMultiplier;
    /**
     * @return (Updatable) The current state of the migration plan.
     * 
     */
    private @Nullable String metricTimeWindow;
    /**
     * @return (Updatable) The current state of the migration plan.
     * 
     */
    private @Nullable String metricType;
    /**
     * @return (Updatable) Percentile value
     * 
     */
    private @Nullable String percentile;
    /**
     * @return (Updatable) The type of resource.
     * 
     */
    private String resourceType;
    /**
     * @return (Updatable) The type of strategy used for migration.
     * 
     */
    private String strategyType;

    private MigrationPlanStrategy() {}
    /**
     * @return (Updatable) The real resource usage is multiplied to this number before making any recommendation.
     * 
     */
    public Optional<Double> adjustmentMultiplier() {
        return Optional.ofNullable(this.adjustmentMultiplier);
    }
    /**
     * @return (Updatable) The current state of the migration plan.
     * 
     */
    public Optional<String> metricTimeWindow() {
        return Optional.ofNullable(this.metricTimeWindow);
    }
    /**
     * @return (Updatable) The current state of the migration plan.
     * 
     */
    public Optional<String> metricType() {
        return Optional.ofNullable(this.metricType);
    }
    /**
     * @return (Updatable) Percentile value
     * 
     */
    public Optional<String> percentile() {
        return Optional.ofNullable(this.percentile);
    }
    /**
     * @return (Updatable) The type of resource.
     * 
     */
    public String resourceType() {
        return this.resourceType;
    }
    /**
     * @return (Updatable) The type of strategy used for migration.
     * 
     */
    public String strategyType() {
        return this.strategyType;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(MigrationPlanStrategy defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable Double adjustmentMultiplier;
        private @Nullable String metricTimeWindow;
        private @Nullable String metricType;
        private @Nullable String percentile;
        private String resourceType;
        private String strategyType;
        public Builder() {}
        public Builder(MigrationPlanStrategy defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.adjustmentMultiplier = defaults.adjustmentMultiplier;
    	      this.metricTimeWindow = defaults.metricTimeWindow;
    	      this.metricType = defaults.metricType;
    	      this.percentile = defaults.percentile;
    	      this.resourceType = defaults.resourceType;
    	      this.strategyType = defaults.strategyType;
        }

        @CustomType.Setter
        public Builder adjustmentMultiplier(@Nullable Double adjustmentMultiplier) {

            this.adjustmentMultiplier = adjustmentMultiplier;
            return this;
        }
        @CustomType.Setter
        public Builder metricTimeWindow(@Nullable String metricTimeWindow) {

            this.metricTimeWindow = metricTimeWindow;
            return this;
        }
        @CustomType.Setter
        public Builder metricType(@Nullable String metricType) {

            this.metricType = metricType;
            return this;
        }
        @CustomType.Setter
        public Builder percentile(@Nullable String percentile) {

            this.percentile = percentile;
            return this;
        }
        @CustomType.Setter
        public Builder resourceType(String resourceType) {
            if (resourceType == null) {
              throw new MissingRequiredPropertyException("MigrationPlanStrategy", "resourceType");
            }
            this.resourceType = resourceType;
            return this;
        }
        @CustomType.Setter
        public Builder strategyType(String strategyType) {
            if (strategyType == null) {
              throw new MissingRequiredPropertyException("MigrationPlanStrategy", "strategyType");
            }
            this.strategyType = strategyType;
            return this;
        }
        public MigrationPlanStrategy build() {
            final var _resultValue = new MigrationPlanStrategy();
            _resultValue.adjustmentMultiplier = adjustmentMultiplier;
            _resultValue.metricTimeWindow = metricTimeWindow;
            _resultValue.metricType = metricType;
            _resultValue.percentile = percentile;
            _resultValue.resourceType = resourceType;
            _resultValue.strategyType = strategyType;
            return _resultValue;
        }
    }
}
