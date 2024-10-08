// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Core.outputs.GetDedicatedVmHostShapesDedicatedVmHostShape;
import com.pulumi.oci.Core.outputs.GetDedicatedVmHostShapesFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetDedicatedVmHostShapesResult {
    /**
     * @return The shape&#39;s availability domain.
     * 
     */
    private @Nullable String availabilityDomain;
    private String compartmentId;
    /**
     * @return The list of dedicated_vm_host_shapes.
     * 
     */
    private List<GetDedicatedVmHostShapesDedicatedVmHostShape> dedicatedVmHostShapes;
    private @Nullable List<GetDedicatedVmHostShapesFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    private @Nullable String instanceShapeName;

    private GetDedicatedVmHostShapesResult() {}
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
     * @return The list of dedicated_vm_host_shapes.
     * 
     */
    public List<GetDedicatedVmHostShapesDedicatedVmHostShape> dedicatedVmHostShapes() {
        return this.dedicatedVmHostShapes;
    }
    public List<GetDedicatedVmHostShapesFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    public Optional<String> instanceShapeName() {
        return Optional.ofNullable(this.instanceShapeName);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDedicatedVmHostShapesResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String availabilityDomain;
        private String compartmentId;
        private List<GetDedicatedVmHostShapesDedicatedVmHostShape> dedicatedVmHostShapes;
        private @Nullable List<GetDedicatedVmHostShapesFilter> filters;
        private String id;
        private @Nullable String instanceShapeName;
        public Builder() {}
        public Builder(GetDedicatedVmHostShapesResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.availabilityDomain = defaults.availabilityDomain;
    	      this.compartmentId = defaults.compartmentId;
    	      this.dedicatedVmHostShapes = defaults.dedicatedVmHostShapes;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.instanceShapeName = defaults.instanceShapeName;
        }

        @CustomType.Setter
        public Builder availabilityDomain(@Nullable String availabilityDomain) {

            this.availabilityDomain = availabilityDomain;
            return this;
        }
        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            if (compartmentId == null) {
              throw new MissingRequiredPropertyException("GetDedicatedVmHostShapesResult", "compartmentId");
            }
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder dedicatedVmHostShapes(List<GetDedicatedVmHostShapesDedicatedVmHostShape> dedicatedVmHostShapes) {
            if (dedicatedVmHostShapes == null) {
              throw new MissingRequiredPropertyException("GetDedicatedVmHostShapesResult", "dedicatedVmHostShapes");
            }
            this.dedicatedVmHostShapes = dedicatedVmHostShapes;
            return this;
        }
        public Builder dedicatedVmHostShapes(GetDedicatedVmHostShapesDedicatedVmHostShape... dedicatedVmHostShapes) {
            return dedicatedVmHostShapes(List.of(dedicatedVmHostShapes));
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetDedicatedVmHostShapesFilter> filters) {

            this.filters = filters;
            return this;
        }
        public Builder filters(GetDedicatedVmHostShapesFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetDedicatedVmHostShapesResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder instanceShapeName(@Nullable String instanceShapeName) {

            this.instanceShapeName = instanceShapeName;
            return this;
        }
        public GetDedicatedVmHostShapesResult build() {
            final var _resultValue = new GetDedicatedVmHostShapesResult();
            _resultValue.availabilityDomain = availabilityDomain;
            _resultValue.compartmentId = compartmentId;
            _resultValue.dedicatedVmHostShapes = dedicatedVmHostShapes;
            _resultValue.filters = filters;
            _resultValue.id = id;
            _resultValue.instanceShapeName = instanceShapeName;
            return _resultValue;
        }
    }
}
