// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Sch.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Sch.outputs.ConnectorTargetDimensionDimensionValue;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class ConnectorTargetDimension {
    /**
     * @return (Updatable) Instructions for extracting the value corresponding to the specified dimension key: Either extract the value as-is (static) or derive the value from a path (evaluated).
     * 
     */
    private final @Nullable ConnectorTargetDimensionDimensionValue dimensionValue;
    /**
     * @return (Updatable) Dimension key. A valid dimension key includes only printable ASCII, excluding periods (.) and spaces. Custom dimension keys are acceptable. Avoid entering confidential information. Due to use by Service Connector Hub, the following dimension names are reserved: `connectorId`, `connectorName`, `connectorSourceType`. For information on valid dimension keys and values, see [MetricDataDetails Reference](https://docs.cloud.oracle.com/iaas/api/#/en/monitoring/latest/datatypes/MetricDataDetails). Example: `type`
     * 
     */
    private final @Nullable String name;

    @CustomType.Constructor
    private ConnectorTargetDimension(
        @CustomType.Parameter("dimensionValue") @Nullable ConnectorTargetDimensionDimensionValue dimensionValue,
        @CustomType.Parameter("name") @Nullable String name) {
        this.dimensionValue = dimensionValue;
        this.name = name;
    }

    /**
     * @return (Updatable) Instructions for extracting the value corresponding to the specified dimension key: Either extract the value as-is (static) or derive the value from a path (evaluated).
     * 
     */
    public Optional<ConnectorTargetDimensionDimensionValue> dimensionValue() {
        return Optional.ofNullable(this.dimensionValue);
    }
    /**
     * @return (Updatable) Dimension key. A valid dimension key includes only printable ASCII, excluding periods (.) and spaces. Custom dimension keys are acceptable. Avoid entering confidential information. Due to use by Service Connector Hub, the following dimension names are reserved: `connectorId`, `connectorName`, `connectorSourceType`. For information on valid dimension keys and values, see [MetricDataDetails Reference](https://docs.cloud.oracle.com/iaas/api/#/en/monitoring/latest/datatypes/MetricDataDetails). Example: `type`
     * 
     */
    public Optional<String> name() {
        return Optional.ofNullable(this.name);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(ConnectorTargetDimension defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private @Nullable ConnectorTargetDimensionDimensionValue dimensionValue;
        private @Nullable String name;

        public Builder() {
    	      // Empty
        }

        public Builder(ConnectorTargetDimension defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.dimensionValue = defaults.dimensionValue;
    	      this.name = defaults.name;
        }

        public Builder dimensionValue(@Nullable ConnectorTargetDimensionDimensionValue dimensionValue) {
            this.dimensionValue = dimensionValue;
            return this;
        }
        public Builder name(@Nullable String name) {
            this.name = name;
            return this;
        }        public ConnectorTargetDimension build() {
            return new ConnectorTargetDimension(dimensionValue, name);
        }
    }
}
