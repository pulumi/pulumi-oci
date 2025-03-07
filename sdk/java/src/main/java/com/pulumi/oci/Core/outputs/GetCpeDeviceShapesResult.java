// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Core.outputs.GetCpeDeviceShapesCpeDeviceShape;
import com.pulumi.oci.Core.outputs.GetCpeDeviceShapesFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import javax.annotation.Nullable;

@CustomType
public final class GetCpeDeviceShapesResult {
    /**
     * @return The list of cpe_device_shapes.
     * 
     */
    private List<GetCpeDeviceShapesCpeDeviceShape> cpeDeviceShapes;
    private @Nullable List<GetCpeDeviceShapesFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;

    private GetCpeDeviceShapesResult() {}
    /**
     * @return The list of cpe_device_shapes.
     * 
     */
    public List<GetCpeDeviceShapesCpeDeviceShape> cpeDeviceShapes() {
        return this.cpeDeviceShapes;
    }
    public List<GetCpeDeviceShapesFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetCpeDeviceShapesResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetCpeDeviceShapesCpeDeviceShape> cpeDeviceShapes;
        private @Nullable List<GetCpeDeviceShapesFilter> filters;
        private String id;
        public Builder() {}
        public Builder(GetCpeDeviceShapesResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.cpeDeviceShapes = defaults.cpeDeviceShapes;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
        }

        @CustomType.Setter
        public Builder cpeDeviceShapes(List<GetCpeDeviceShapesCpeDeviceShape> cpeDeviceShapes) {
            if (cpeDeviceShapes == null) {
              throw new MissingRequiredPropertyException("GetCpeDeviceShapesResult", "cpeDeviceShapes");
            }
            this.cpeDeviceShapes = cpeDeviceShapes;
            return this;
        }
        public Builder cpeDeviceShapes(GetCpeDeviceShapesCpeDeviceShape... cpeDeviceShapes) {
            return cpeDeviceShapes(List.of(cpeDeviceShapes));
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetCpeDeviceShapesFilter> filters) {

            this.filters = filters;
            return this;
        }
        public Builder filters(GetCpeDeviceShapesFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetCpeDeviceShapesResult", "id");
            }
            this.id = id;
            return this;
        }
        public GetCpeDeviceShapesResult build() {
            final var _resultValue = new GetCpeDeviceShapesResult();
            _resultValue.cpeDeviceShapes = cpeDeviceShapes;
            _resultValue.filters = filters;
            _resultValue.id = id;
            return _resultValue;
        }
    }
}
