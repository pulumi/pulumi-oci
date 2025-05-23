// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CloudMigrations.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Double;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetMigrationPlansMigrationPlanCollectionItemStrategy {
    /**
     * @return The real resource usage is multiplied to this number before making any recommendation.
     * 
     */
    private Double adjustmentMultiplier;
    /**
     * @return The current state of the migration plan.
     * 
     */
    private String metricTimeWindow;
    /**
     * @return The current state of the migration plan.
     * 
     */
    private String metricType;
    /**
     * @return Percentile value
     * 
     */
    private String percentile;
    /**
     * @return The type of resource.
     * 
     */
    private String resourceType;
    /**
     * @return The type of strategy used for migration.
     * 
     */
    private String strategyType;

    private GetMigrationPlansMigrationPlanCollectionItemStrategy() {}
    /**
     * @return The real resource usage is multiplied to this number before making any recommendation.
     * 
     */
    public Double adjustmentMultiplier() {
        return this.adjustmentMultiplier;
    }
    /**
     * @return The current state of the migration plan.
     * 
     */
    public String metricTimeWindow() {
        return this.metricTimeWindow;
    }
    /**
     * @return The current state of the migration plan.
     * 
     */
    public String metricType() {
        return this.metricType;
    }
    /**
     * @return Percentile value
     * 
     */
    public String percentile() {
        return this.percentile;
    }
    /**
     * @return The type of resource.
     * 
     */
    public String resourceType() {
        return this.resourceType;
    }
    /**
     * @return The type of strategy used for migration.
     * 
     */
    public String strategyType() {
        return this.strategyType;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetMigrationPlansMigrationPlanCollectionItemStrategy defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private Double adjustmentMultiplier;
        private String metricTimeWindow;
        private String metricType;
        private String percentile;
        private String resourceType;
        private String strategyType;
        public Builder() {}
        public Builder(GetMigrationPlansMigrationPlanCollectionItemStrategy defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.adjustmentMultiplier = defaults.adjustmentMultiplier;
    	      this.metricTimeWindow = defaults.metricTimeWindow;
    	      this.metricType = defaults.metricType;
    	      this.percentile = defaults.percentile;
    	      this.resourceType = defaults.resourceType;
    	      this.strategyType = defaults.strategyType;
        }

        @CustomType.Setter
        public Builder adjustmentMultiplier(Double adjustmentMultiplier) {
            if (adjustmentMultiplier == null) {
              throw new MissingRequiredPropertyException("GetMigrationPlansMigrationPlanCollectionItemStrategy", "adjustmentMultiplier");
            }
            this.adjustmentMultiplier = adjustmentMultiplier;
            return this;
        }
        @CustomType.Setter
        public Builder metricTimeWindow(String metricTimeWindow) {
            if (metricTimeWindow == null) {
              throw new MissingRequiredPropertyException("GetMigrationPlansMigrationPlanCollectionItemStrategy", "metricTimeWindow");
            }
            this.metricTimeWindow = metricTimeWindow;
            return this;
        }
        @CustomType.Setter
        public Builder metricType(String metricType) {
            if (metricType == null) {
              throw new MissingRequiredPropertyException("GetMigrationPlansMigrationPlanCollectionItemStrategy", "metricType");
            }
            this.metricType = metricType;
            return this;
        }
        @CustomType.Setter
        public Builder percentile(String percentile) {
            if (percentile == null) {
              throw new MissingRequiredPropertyException("GetMigrationPlansMigrationPlanCollectionItemStrategy", "percentile");
            }
            this.percentile = percentile;
            return this;
        }
        @CustomType.Setter
        public Builder resourceType(String resourceType) {
            if (resourceType == null) {
              throw new MissingRequiredPropertyException("GetMigrationPlansMigrationPlanCollectionItemStrategy", "resourceType");
            }
            this.resourceType = resourceType;
            return this;
        }
        @CustomType.Setter
        public Builder strategyType(String strategyType) {
            if (strategyType == null) {
              throw new MissingRequiredPropertyException("GetMigrationPlansMigrationPlanCollectionItemStrategy", "strategyType");
            }
            this.strategyType = strategyType;
            return this;
        }
        public GetMigrationPlansMigrationPlanCollectionItemStrategy build() {
            final var _resultValue = new GetMigrationPlansMigrationPlanCollectionItemStrategy();
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
