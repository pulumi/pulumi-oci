// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Core.outputs.GetInstanceDevicesDevice;
import com.pulumi.oci.Core.outputs.GetInstanceDevicesFilter;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetInstanceDevicesResult {
    /**
     * @return The list of devices.
     * 
     */
    private List<GetInstanceDevicesDevice> devices;
    private @Nullable List<GetInstanceDevicesFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    private String instanceId;
    /**
     * @return The flag denoting whether device is available.
     * 
     */
    private @Nullable Boolean isAvailable;
    /**
     * @return The device name.
     * 
     */
    private @Nullable String name;

    private GetInstanceDevicesResult() {}
    /**
     * @return The list of devices.
     * 
     */
    public List<GetInstanceDevicesDevice> devices() {
        return this.devices;
    }
    public List<GetInstanceDevicesFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    public String instanceId() {
        return this.instanceId;
    }
    /**
     * @return The flag denoting whether device is available.
     * 
     */
    public Optional<Boolean> isAvailable() {
        return Optional.ofNullable(this.isAvailable);
    }
    /**
     * @return The device name.
     * 
     */
    public Optional<String> name() {
        return Optional.ofNullable(this.name);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetInstanceDevicesResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetInstanceDevicesDevice> devices;
        private @Nullable List<GetInstanceDevicesFilter> filters;
        private String id;
        private String instanceId;
        private @Nullable Boolean isAvailable;
        private @Nullable String name;
        public Builder() {}
        public Builder(GetInstanceDevicesResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.devices = defaults.devices;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.instanceId = defaults.instanceId;
    	      this.isAvailable = defaults.isAvailable;
    	      this.name = defaults.name;
        }

        @CustomType.Setter
        public Builder devices(List<GetInstanceDevicesDevice> devices) {
            this.devices = Objects.requireNonNull(devices);
            return this;
        }
        public Builder devices(GetInstanceDevicesDevice... devices) {
            return devices(List.of(devices));
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetInstanceDevicesFilter> filters) {
            this.filters = filters;
            return this;
        }
        public Builder filters(GetInstanceDevicesFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        @CustomType.Setter
        public Builder instanceId(String instanceId) {
            this.instanceId = Objects.requireNonNull(instanceId);
            return this;
        }
        @CustomType.Setter
        public Builder isAvailable(@Nullable Boolean isAvailable) {
            this.isAvailable = isAvailable;
            return this;
        }
        @CustomType.Setter
        public Builder name(@Nullable String name) {
            this.name = name;
            return this;
        }
        public GetInstanceDevicesResult build() {
            final var o = new GetInstanceDevicesResult();
            o.devices = devices;
            o.filters = filters;
            o.id = id;
            o.instanceId = instanceId;
            o.isAvailable = isAvailable;
            o.name = name;
            return o;
        }
    }
}