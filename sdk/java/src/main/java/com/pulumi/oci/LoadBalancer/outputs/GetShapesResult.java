// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.LoadBalancer.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.LoadBalancer.outputs.GetShapesFilter;
import com.pulumi.oci.LoadBalancer.outputs.GetShapesShape;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import javax.annotation.Nullable;

@CustomType
public final class GetShapesResult {
    private String compartmentId;
    private @Nullable List<GetShapesFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return The list of shapes.
     * 
     */
    private List<GetShapesShape> shapes;

    private GetShapesResult() {}
    public String compartmentId() {
        return this.compartmentId;
    }
    public List<GetShapesFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return The list of shapes.
     * 
     */
    public List<GetShapesShape> shapes() {
        return this.shapes;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetShapesResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String compartmentId;
        private @Nullable List<GetShapesFilter> filters;
        private String id;
        private List<GetShapesShape> shapes;
        public Builder() {}
        public Builder(GetShapesResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.shapes = defaults.shapes;
        }

        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            if (compartmentId == null) {
              throw new MissingRequiredPropertyException("GetShapesResult", "compartmentId");
            }
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetShapesFilter> filters) {

            this.filters = filters;
            return this;
        }
        public Builder filters(GetShapesFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetShapesResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder shapes(List<GetShapesShape> shapes) {
            if (shapes == null) {
              throw new MissingRequiredPropertyException("GetShapesResult", "shapes");
            }
            this.shapes = shapes;
            return this;
        }
        public Builder shapes(GetShapesShape... shapes) {
            return shapes(List.of(shapes));
        }
        public GetShapesResult build() {
            final var _resultValue = new GetShapesResult();
            _resultValue.compartmentId = compartmentId;
            _resultValue.filters = filters;
            _resultValue.id = id;
            _resultValue.shapes = shapes;
            return _resultValue;
        }
    }
}
