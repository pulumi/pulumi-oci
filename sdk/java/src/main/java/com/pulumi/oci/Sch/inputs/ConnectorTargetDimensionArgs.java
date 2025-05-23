// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Sch.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.Sch.inputs.ConnectorTargetDimensionDimensionValueArgs;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class ConnectorTargetDimensionArgs extends com.pulumi.resources.ResourceArgs {

    public static final ConnectorTargetDimensionArgs Empty = new ConnectorTargetDimensionArgs();

    /**
     * (Updatable) Instructions for extracting the value corresponding to the specified dimension key: Either extract the value as-is (static) or derive the value from a path (evaluated).
     * 
     */
    @Import(name="dimensionValue")
    private @Nullable Output<ConnectorTargetDimensionDimensionValueArgs> dimensionValue;

    /**
     * @return (Updatable) Instructions for extracting the value corresponding to the specified dimension key: Either extract the value as-is (static) or derive the value from a path (evaluated).
     * 
     */
    public Optional<Output<ConnectorTargetDimensionDimensionValueArgs>> dimensionValue() {
        return Optional.ofNullable(this.dimensionValue);
    }

    /**
     * (Updatable) Dimension key. A valid dimension key includes only printable ASCII, excluding periods (.) and spaces. Custom dimension keys are acceptable. Avoid entering confidential information. Due to use by Connector Hub, the following dimension names are reserved: `connectorId`, `connectorName`, `connectorSourceType`. For information on valid dimension keys and values, see [MetricDataDetails Reference](https://docs.cloud.oracle.com/iaas/api/#/en/monitoring/latest/datatypes/MetricDataDetails). Example: `type`
     * 
     */
    @Import(name="name")
    private @Nullable Output<String> name;

    /**
     * @return (Updatable) Dimension key. A valid dimension key includes only printable ASCII, excluding periods (.) and spaces. Custom dimension keys are acceptable. Avoid entering confidential information. Due to use by Connector Hub, the following dimension names are reserved: `connectorId`, `connectorName`, `connectorSourceType`. For information on valid dimension keys and values, see [MetricDataDetails Reference](https://docs.cloud.oracle.com/iaas/api/#/en/monitoring/latest/datatypes/MetricDataDetails). Example: `type`
     * 
     */
    public Optional<Output<String>> name() {
        return Optional.ofNullable(this.name);
    }

    private ConnectorTargetDimensionArgs() {}

    private ConnectorTargetDimensionArgs(ConnectorTargetDimensionArgs $) {
        this.dimensionValue = $.dimensionValue;
        this.name = $.name;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(ConnectorTargetDimensionArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private ConnectorTargetDimensionArgs $;

        public Builder() {
            $ = new ConnectorTargetDimensionArgs();
        }

        public Builder(ConnectorTargetDimensionArgs defaults) {
            $ = new ConnectorTargetDimensionArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param dimensionValue (Updatable) Instructions for extracting the value corresponding to the specified dimension key: Either extract the value as-is (static) or derive the value from a path (evaluated).
         * 
         * @return builder
         * 
         */
        public Builder dimensionValue(@Nullable Output<ConnectorTargetDimensionDimensionValueArgs> dimensionValue) {
            $.dimensionValue = dimensionValue;
            return this;
        }

        /**
         * @param dimensionValue (Updatable) Instructions for extracting the value corresponding to the specified dimension key: Either extract the value as-is (static) or derive the value from a path (evaluated).
         * 
         * @return builder
         * 
         */
        public Builder dimensionValue(ConnectorTargetDimensionDimensionValueArgs dimensionValue) {
            return dimensionValue(Output.of(dimensionValue));
        }

        /**
         * @param name (Updatable) Dimension key. A valid dimension key includes only printable ASCII, excluding periods (.) and spaces. Custom dimension keys are acceptable. Avoid entering confidential information. Due to use by Connector Hub, the following dimension names are reserved: `connectorId`, `connectorName`, `connectorSourceType`. For information on valid dimension keys and values, see [MetricDataDetails Reference](https://docs.cloud.oracle.com/iaas/api/#/en/monitoring/latest/datatypes/MetricDataDetails). Example: `type`
         * 
         * @return builder
         * 
         */
        public Builder name(@Nullable Output<String> name) {
            $.name = name;
            return this;
        }

        /**
         * @param name (Updatable) Dimension key. A valid dimension key includes only printable ASCII, excluding periods (.) and spaces. Custom dimension keys are acceptable. Avoid entering confidential information. Due to use by Connector Hub, the following dimension names are reserved: `connectorId`, `connectorName`, `connectorSourceType`. For information on valid dimension keys and values, see [MetricDataDetails Reference](https://docs.cloud.oracle.com/iaas/api/#/en/monitoring/latest/datatypes/MetricDataDetails). Example: `type`
         * 
         * @return builder
         * 
         */
        public Builder name(String name) {
            return name(Output.of(name));
        }

        public ConnectorTargetDimensionArgs build() {
            return $;
        }
    }

}
