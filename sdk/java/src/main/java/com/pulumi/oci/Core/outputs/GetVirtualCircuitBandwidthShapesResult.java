// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Core.outputs.GetVirtualCircuitBandwidthShapesFilter;
import com.pulumi.oci.Core.outputs.GetVirtualCircuitBandwidthShapesVirtualCircuitBandwidthShape;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import javax.annotation.Nullable;

@CustomType
public final class GetVirtualCircuitBandwidthShapesResult {
    private @Nullable List<GetVirtualCircuitBandwidthShapesFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    private String providerServiceId;
    /**
     * @return The list of virtual_circuit_bandwidth_shapes.
     * 
     */
    private List<GetVirtualCircuitBandwidthShapesVirtualCircuitBandwidthShape> virtualCircuitBandwidthShapes;

    private GetVirtualCircuitBandwidthShapesResult() {}
    public List<GetVirtualCircuitBandwidthShapesFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    public String providerServiceId() {
        return this.providerServiceId;
    }
    /**
     * @return The list of virtual_circuit_bandwidth_shapes.
     * 
     */
    public List<GetVirtualCircuitBandwidthShapesVirtualCircuitBandwidthShape> virtualCircuitBandwidthShapes() {
        return this.virtualCircuitBandwidthShapes;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetVirtualCircuitBandwidthShapesResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable List<GetVirtualCircuitBandwidthShapesFilter> filters;
        private String id;
        private String providerServiceId;
        private List<GetVirtualCircuitBandwidthShapesVirtualCircuitBandwidthShape> virtualCircuitBandwidthShapes;
        public Builder() {}
        public Builder(GetVirtualCircuitBandwidthShapesResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.providerServiceId = defaults.providerServiceId;
    	      this.virtualCircuitBandwidthShapes = defaults.virtualCircuitBandwidthShapes;
        }

        @CustomType.Setter
        public Builder filters(@Nullable List<GetVirtualCircuitBandwidthShapesFilter> filters) {
            this.filters = filters;
            return this;
        }
        public Builder filters(GetVirtualCircuitBandwidthShapesFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        @CustomType.Setter
        public Builder providerServiceId(String providerServiceId) {
            this.providerServiceId = Objects.requireNonNull(providerServiceId);
            return this;
        }
        @CustomType.Setter
        public Builder virtualCircuitBandwidthShapes(List<GetVirtualCircuitBandwidthShapesVirtualCircuitBandwidthShape> virtualCircuitBandwidthShapes) {
            this.virtualCircuitBandwidthShapes = Objects.requireNonNull(virtualCircuitBandwidthShapes);
            return this;
        }
        public Builder virtualCircuitBandwidthShapes(GetVirtualCircuitBandwidthShapesVirtualCircuitBandwidthShape... virtualCircuitBandwidthShapes) {
            return virtualCircuitBandwidthShapes(List.of(virtualCircuitBandwidthShapes));
        }
        public GetVirtualCircuitBandwidthShapesResult build() {
            final var o = new GetVirtualCircuitBandwidthShapesResult();
            o.filters = filters;
            o.id = id;
            o.providerServiceId = providerServiceId;
            o.virtualCircuitBandwidthShapes = virtualCircuitBandwidthShapes;
            return o;
        }
    }
}