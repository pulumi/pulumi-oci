// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.StackMonitoring.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Object;
import java.lang.String;
import java.util.Map;
import java.util.Objects;
import javax.annotation.Nullable;

@CustomType
public final class DiscoveryJobDiscoveryDetailsProperties {
    /**
     * @return Key/Value pair of Property
     * 
     */
    private @Nullable Map<String,Object> propertiesMap;

    private DiscoveryJobDiscoveryDetailsProperties() {}
    /**
     * @return Key/Value pair of Property
     * 
     */
    public Map<String,Object> propertiesMap() {
        return this.propertiesMap == null ? Map.of() : this.propertiesMap;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(DiscoveryJobDiscoveryDetailsProperties defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable Map<String,Object> propertiesMap;
        public Builder() {}
        public Builder(DiscoveryJobDiscoveryDetailsProperties defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.propertiesMap = defaults.propertiesMap;
        }

        @CustomType.Setter
        public Builder propertiesMap(@Nullable Map<String,Object> propertiesMap) {
            this.propertiesMap = propertiesMap;
            return this;
        }
        public DiscoveryJobDiscoveryDetailsProperties build() {
            final var o = new DiscoveryJobDiscoveryDetailsProperties();
            o.propertiesMap = propertiesMap;
            return o;
        }
    }
}