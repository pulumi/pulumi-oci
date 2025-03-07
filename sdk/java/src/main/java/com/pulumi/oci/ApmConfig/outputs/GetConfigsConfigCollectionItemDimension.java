// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ApmConfig.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetConfigsConfigCollectionItemDimension {
    /**
     * @return The name of the metric. This must be a known metric name.
     * 
     */
    private String name;
    /**
     * @return This must not be set.
     * 
     */
    private String valueSource;

    private GetConfigsConfigCollectionItemDimension() {}
    /**
     * @return The name of the metric. This must be a known metric name.
     * 
     */
    public String name() {
        return this.name;
    }
    /**
     * @return This must not be set.
     * 
     */
    public String valueSource() {
        return this.valueSource;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetConfigsConfigCollectionItemDimension defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String name;
        private String valueSource;
        public Builder() {}
        public Builder(GetConfigsConfigCollectionItemDimension defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.name = defaults.name;
    	      this.valueSource = defaults.valueSource;
        }

        @CustomType.Setter
        public Builder name(String name) {
            if (name == null) {
              throw new MissingRequiredPropertyException("GetConfigsConfigCollectionItemDimension", "name");
            }
            this.name = name;
            return this;
        }
        @CustomType.Setter
        public Builder valueSource(String valueSource) {
            if (valueSource == null) {
              throw new MissingRequiredPropertyException("GetConfigsConfigCollectionItemDimension", "valueSource");
            }
            this.valueSource = valueSource;
            return this;
        }
        public GetConfigsConfigCollectionItemDimension build() {
            final var _resultValue = new GetConfigsConfigCollectionItemDimension();
            _resultValue.name = name;
            _resultValue.valueSource = valueSource;
            return _resultValue;
        }
    }
}
