// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Psql.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Psql.outputs.GetConfigurationsConfigurationCollectionItem;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetConfigurationsConfigurationCollection {
    /**
     * @return List of ConfigParms object.
     * 
     */
    private List<GetConfigurationsConfigurationCollectionItem> items;

    private GetConfigurationsConfigurationCollection() {}
    /**
     * @return List of ConfigParms object.
     * 
     */
    public List<GetConfigurationsConfigurationCollectionItem> items() {
        return this.items;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetConfigurationsConfigurationCollection defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetConfigurationsConfigurationCollectionItem> items;
        public Builder() {}
        public Builder(GetConfigurationsConfigurationCollection defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
        }

        @CustomType.Setter
        public Builder items(List<GetConfigurationsConfigurationCollectionItem> items) {
            if (items == null) {
              throw new MissingRequiredPropertyException("GetConfigurationsConfigurationCollection", "items");
            }
            this.items = items;
            return this;
        }
        public Builder items(GetConfigurationsConfigurationCollectionItem... items) {
            return items(List.of(items));
        }
        public GetConfigurationsConfigurationCollection build() {
            final var _resultValue = new GetConfigurationsConfigurationCollection();
            _resultValue.items = items;
            return _resultValue;
        }
    }
}
