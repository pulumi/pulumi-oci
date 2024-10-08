// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
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
            if (id == null) {
              throw new MissingRequiredPropertyException("GetVirtualCircuitBandwidthShapesResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder providerServiceId(String providerServiceId) {
            if (providerServiceId == null) {
              throw new MissingRequiredPropertyException("GetVirtualCircuitBandwidthShapesResult", "providerServiceId");
            }
            this.providerServiceId = providerServiceId;
            return this;
        }
        @CustomType.Setter
        public Builder virtualCircuitBandwidthShapes(List<GetVirtualCircuitBandwidthShapesVirtualCircuitBandwidthShape> virtualCircuitBandwidthShapes) {
            if (virtualCircuitBandwidthShapes == null) {
              throw new MissingRequiredPropertyException("GetVirtualCircuitBandwidthShapesResult", "virtualCircuitBandwidthShapes");
            }
            this.virtualCircuitBandwidthShapes = virtualCircuitBandwidthShapes;
            return this;
        }
        public Builder virtualCircuitBandwidthShapes(GetVirtualCircuitBandwidthShapesVirtualCircuitBandwidthShape... virtualCircuitBandwidthShapes) {
            return virtualCircuitBandwidthShapes(List.of(virtualCircuitBandwidthShapes));
        }
        public GetVirtualCircuitBandwidthShapesResult build() {
            final var _resultValue = new GetVirtualCircuitBandwidthShapesResult();
            _resultValue.filters = filters;
            _resultValue.id = id;
            _resultValue.providerServiceId = providerServiceId;
            _resultValue.virtualCircuitBandwidthShapes = virtualCircuitBandwidthShapes;
            return _resultValue;
        }
    }
}
