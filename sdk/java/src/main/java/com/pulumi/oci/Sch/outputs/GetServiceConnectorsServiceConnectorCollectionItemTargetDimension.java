// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Sch.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Sch.outputs.GetServiceConnectorsServiceConnectorCollectionItemTargetDimensionDimensionValue;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetServiceConnectorsServiceConnectorCollectionItemTargetDimension {
    /**
     * @return Instructions for extracting the value corresponding to the specified dimension key: Either extract the value as-is (static) or derive the value from a path (evaluated).
     * 
     */
    private final List<GetServiceConnectorsServiceConnectorCollectionItemTargetDimensionDimensionValue> dimensionValues;
    /**
     * @return Dimension key. A valid dimension key includes only printable ASCII, excluding periods (.) and spaces. Custom dimension keys are acceptable. Avoid entering confidential information. Due to use by Service Connector Hub, the following dimension names are reserved: `connectorId`, `connectorName`, `connectorSourceType`. For information on valid dimension keys and values, see [MetricDataDetails Reference](https://docs.cloud.oracle.com/iaas/api/#/en/monitoring/latest/datatypes/MetricDataDetails). Example: `type`
     * 
     */
    private final String name;

    @CustomType.Constructor
    private GetServiceConnectorsServiceConnectorCollectionItemTargetDimension(
        @CustomType.Parameter("dimensionValues") List<GetServiceConnectorsServiceConnectorCollectionItemTargetDimensionDimensionValue> dimensionValues,
        @CustomType.Parameter("name") String name) {
        this.dimensionValues = dimensionValues;
        this.name = name;
    }

    /**
     * @return Instructions for extracting the value corresponding to the specified dimension key: Either extract the value as-is (static) or derive the value from a path (evaluated).
     * 
     */
    public List<GetServiceConnectorsServiceConnectorCollectionItemTargetDimensionDimensionValue> dimensionValues() {
        return this.dimensionValues;
    }
    /**
     * @return Dimension key. A valid dimension key includes only printable ASCII, excluding periods (.) and spaces. Custom dimension keys are acceptable. Avoid entering confidential information. Due to use by Service Connector Hub, the following dimension names are reserved: `connectorId`, `connectorName`, `connectorSourceType`. For information on valid dimension keys and values, see [MetricDataDetails Reference](https://docs.cloud.oracle.com/iaas/api/#/en/monitoring/latest/datatypes/MetricDataDetails). Example: `type`
     * 
     */
    public String name() {
        return this.name;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetServiceConnectorsServiceConnectorCollectionItemTargetDimension defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private List<GetServiceConnectorsServiceConnectorCollectionItemTargetDimensionDimensionValue> dimensionValues;
        private String name;

        public Builder() {
    	      // Empty
        }

        public Builder(GetServiceConnectorsServiceConnectorCollectionItemTargetDimension defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.dimensionValues = defaults.dimensionValues;
    	      this.name = defaults.name;
        }

        public Builder dimensionValues(List<GetServiceConnectorsServiceConnectorCollectionItemTargetDimensionDimensionValue> dimensionValues) {
            this.dimensionValues = Objects.requireNonNull(dimensionValues);
            return this;
        }
        public Builder dimensionValues(GetServiceConnectorsServiceConnectorCollectionItemTargetDimensionDimensionValue... dimensionValues) {
            return dimensionValues(List.of(dimensionValues));
        }
        public Builder name(String name) {
            this.name = Objects.requireNonNull(name);
            return this;
        }        public GetServiceConnectorsServiceConnectorCollectionItemTargetDimension build() {
            return new GetServiceConnectorsServiceConnectorCollectionItemTargetDimension(dimensionValues, name);
        }
    }
}
