// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.StackMonitoring.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class MonitoredResourcesSearchItemProperty {
    /**
     * @return A filter to return resources that match exact resource name
     * 
     */
    private @Nullable String name;
    /**
     * @return property value
     * 
     */
    private @Nullable String value;

    private MonitoredResourcesSearchItemProperty() {}
    /**
     * @return A filter to return resources that match exact resource name
     * 
     */
    public Optional<String> name() {
        return Optional.ofNullable(this.name);
    }
    /**
     * @return property value
     * 
     */
    public Optional<String> value() {
        return Optional.ofNullable(this.value);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(MonitoredResourcesSearchItemProperty defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String name;
        private @Nullable String value;
        public Builder() {}
        public Builder(MonitoredResourcesSearchItemProperty defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.name = defaults.name;
    	      this.value = defaults.value;
        }

        @CustomType.Setter
        public Builder name(@Nullable String name) {
            this.name = name;
            return this;
        }
        @CustomType.Setter
        public Builder value(@Nullable String value) {
            this.value = value;
            return this;
        }
        public MonitoredResourcesSearchItemProperty build() {
            final var o = new MonitoredResourcesSearchItemProperty();
            o.name = name;
            o.value = value;
            return o;
        }
    }
}