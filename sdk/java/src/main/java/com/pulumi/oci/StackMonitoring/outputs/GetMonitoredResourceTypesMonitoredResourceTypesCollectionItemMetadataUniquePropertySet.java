// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.StackMonitoring.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetMonitoredResourceTypesMonitoredResourceTypesCollectionItemMetadataUniquePropertySet {
    /**
     * @return List of properties.
     * 
     */
    private List<String> properties;

    private GetMonitoredResourceTypesMonitoredResourceTypesCollectionItemMetadataUniquePropertySet() {}
    /**
     * @return List of properties.
     * 
     */
    public List<String> properties() {
        return this.properties;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetMonitoredResourceTypesMonitoredResourceTypesCollectionItemMetadataUniquePropertySet defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<String> properties;
        public Builder() {}
        public Builder(GetMonitoredResourceTypesMonitoredResourceTypesCollectionItemMetadataUniquePropertySet defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.properties = defaults.properties;
        }

        @CustomType.Setter
        public Builder properties(List<String> properties) {
            if (properties == null) {
              throw new MissingRequiredPropertyException("GetMonitoredResourceTypesMonitoredResourceTypesCollectionItemMetadataUniquePropertySet", "properties");
            }
            this.properties = properties;
            return this;
        }
        public Builder properties(String... properties) {
            return properties(List.of(properties));
        }
        public GetMonitoredResourceTypesMonitoredResourceTypesCollectionItemMetadataUniquePropertySet build() {
            final var _resultValue = new GetMonitoredResourceTypesMonitoredResourceTypesCollectionItemMetadataUniquePropertySet();
            _resultValue.properties = properties;
            return _resultValue;
        }
    }
}
