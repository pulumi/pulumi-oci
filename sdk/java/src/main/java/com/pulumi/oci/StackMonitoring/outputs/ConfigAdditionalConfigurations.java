// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.StackMonitoring.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Map;
import java.util.Objects;
import javax.annotation.Nullable;

@CustomType
public final class ConfigAdditionalConfigurations {
    /**
     * @return (Updatable) Key/Value pair of Property
     * 
     */
    private @Nullable Map<String,String> propertiesMap;

    private ConfigAdditionalConfigurations() {}
    /**
     * @return (Updatable) Key/Value pair of Property
     * 
     */
    public Map<String,String> propertiesMap() {
        return this.propertiesMap == null ? Map.of() : this.propertiesMap;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(ConfigAdditionalConfigurations defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable Map<String,String> propertiesMap;
        public Builder() {}
        public Builder(ConfigAdditionalConfigurations defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.propertiesMap = defaults.propertiesMap;
        }

        @CustomType.Setter
        public Builder propertiesMap(@Nullable Map<String,String> propertiesMap) {

            this.propertiesMap = propertiesMap;
            return this;
        }
        public ConfigAdditionalConfigurations build() {
            final var _resultValue = new ConfigAdditionalConfigurations();
            _resultValue.propertiesMap = propertiesMap;
            return _resultValue;
        }
    }
}
