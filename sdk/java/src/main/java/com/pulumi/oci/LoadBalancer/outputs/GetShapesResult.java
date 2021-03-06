// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.LoadBalancer.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.LoadBalancer.outputs.GetShapesFilter;
import com.pulumi.oci.LoadBalancer.outputs.GetShapesShape;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import javax.annotation.Nullable;

@CustomType
public final class GetShapesResult {
    private final String compartmentId;
    private final @Nullable List<GetShapesFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private final String id;
    /**
     * @return The list of shapes.
     * 
     */
    private final List<GetShapesShape> shapes;

    @CustomType.Constructor
    private GetShapesResult(
        @CustomType.Parameter("compartmentId") String compartmentId,
        @CustomType.Parameter("filters") @Nullable List<GetShapesFilter> filters,
        @CustomType.Parameter("id") String id,
        @CustomType.Parameter("shapes") List<GetShapesShape> shapes) {
        this.compartmentId = compartmentId;
        this.filters = filters;
        this.id = id;
        this.shapes = shapes;
    }

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

    public static final class Builder {
        private String compartmentId;
        private @Nullable List<GetShapesFilter> filters;
        private String id;
        private List<GetShapesShape> shapes;

        public Builder() {
    	      // Empty
        }

        public Builder(GetShapesResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.shapes = defaults.shapes;
        }

        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        public Builder filters(@Nullable List<GetShapesFilter> filters) {
            this.filters = filters;
            return this;
        }
        public Builder filters(GetShapesFilter... filters) {
            return filters(List.of(filters));
        }
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        public Builder shapes(List<GetShapesShape> shapes) {
            this.shapes = Objects.requireNonNull(shapes);
            return this;
        }
        public Builder shapes(GetShapesShape... shapes) {
            return shapes(List.of(shapes));
        }        public GetShapesResult build() {
            return new GetShapesResult(compartmentId, filters, id, shapes);
        }
    }
}
