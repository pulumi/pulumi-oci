// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Core.outputs.GetComputeCapacityReservationInstanceShapesComputeCapacityReservationInstanceShape;
import com.pulumi.oci.Core.outputs.GetComputeCapacityReservationInstanceShapesFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetComputeCapacityReservationInstanceShapesResult {
    /**
     * @return The shape&#39;s availability domain.
     * 
     */
    private @Nullable String availabilityDomain;
    private String compartmentId;
    /**
     * @return The list of compute_capacity_reservation_instance_shapes.
     * 
     */
    private List<GetComputeCapacityReservationInstanceShapesComputeCapacityReservationInstanceShape> computeCapacityReservationInstanceShapes;
    private @Nullable String displayName;
    private @Nullable List<GetComputeCapacityReservationInstanceShapesFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;

    private GetComputeCapacityReservationInstanceShapesResult() {}
    /**
     * @return The shape&#39;s availability domain.
     * 
     */
    public Optional<String> availabilityDomain() {
        return Optional.ofNullable(this.availabilityDomain);
    }
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return The list of compute_capacity_reservation_instance_shapes.
     * 
     */
    public List<GetComputeCapacityReservationInstanceShapesComputeCapacityReservationInstanceShape> computeCapacityReservationInstanceShapes() {
        return this.computeCapacityReservationInstanceShapes;
    }
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }
    public List<GetComputeCapacityReservationInstanceShapesFilter> filters() {
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

    public static Builder builder(GetComputeCapacityReservationInstanceShapesResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String availabilityDomain;
        private String compartmentId;
        private List<GetComputeCapacityReservationInstanceShapesComputeCapacityReservationInstanceShape> computeCapacityReservationInstanceShapes;
        private @Nullable String displayName;
        private @Nullable List<GetComputeCapacityReservationInstanceShapesFilter> filters;
        private String id;
        public Builder() {}
        public Builder(GetComputeCapacityReservationInstanceShapesResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.availabilityDomain = defaults.availabilityDomain;
    	      this.compartmentId = defaults.compartmentId;
    	      this.computeCapacityReservationInstanceShapes = defaults.computeCapacityReservationInstanceShapes;
    	      this.displayName = defaults.displayName;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
        }

        @CustomType.Setter
        public Builder availabilityDomain(@Nullable String availabilityDomain) {
            this.availabilityDomain = availabilityDomain;
            return this;
        }
        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        @CustomType.Setter
        public Builder computeCapacityReservationInstanceShapes(List<GetComputeCapacityReservationInstanceShapesComputeCapacityReservationInstanceShape> computeCapacityReservationInstanceShapes) {
            this.computeCapacityReservationInstanceShapes = Objects.requireNonNull(computeCapacityReservationInstanceShapes);
            return this;
        }
        public Builder computeCapacityReservationInstanceShapes(GetComputeCapacityReservationInstanceShapesComputeCapacityReservationInstanceShape... computeCapacityReservationInstanceShapes) {
            return computeCapacityReservationInstanceShapes(List.of(computeCapacityReservationInstanceShapes));
        }
        @CustomType.Setter
        public Builder displayName(@Nullable String displayName) {
            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetComputeCapacityReservationInstanceShapesFilter> filters) {
            this.filters = filters;
            return this;
        }
        public Builder filters(GetComputeCapacityReservationInstanceShapesFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        public GetComputeCapacityReservationInstanceShapesResult build() {
            final var o = new GetComputeCapacityReservationInstanceShapesResult();
            o.availabilityDomain = availabilityDomain;
            o.compartmentId = compartmentId;
            o.computeCapacityReservationInstanceShapes = computeCapacityReservationInstanceShapes;
            o.displayName = displayName;
            o.filters = filters;
            o.id = id;
            return o;
        }
    }
}