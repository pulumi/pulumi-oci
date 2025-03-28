// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Core.outputs.GetInstancesFilter;
import com.pulumi.oci.Core.outputs.GetInstancesInstance;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetInstancesResult {
    /**
     * @return The availability domain the instance is running in.  Example: `Uocm:PHX-AD-1`
     * 
     */
    private @Nullable String availabilityDomain;
    /**
     * @return The OCID of the compute capacity reservation this instance is launched under. When this field contains an empty string or is null, the instance is not currently in a capacity reservation. For more information, see [Capacity Reservations](https://docs.cloud.oracle.com/iaas/Content/Compute/Tasks/reserve-capacity.htm#default).
     * 
     */
    private @Nullable String capacityReservationId;
    /**
     * @return The OCID of the compartment containing images to search
     * 
     */
    private String compartmentId;
    private @Nullable String computeClusterId;
    /**
     * @return A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    private @Nullable String displayName;
    private @Nullable List<GetInstancesFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return The list of instances.
     * 
     */
    private List<GetInstancesInstance> instances;
    /**
     * @return The current state of the instance.
     * 
     */
    private @Nullable String state;

    private GetInstancesResult() {}
    /**
     * @return The availability domain the instance is running in.  Example: `Uocm:PHX-AD-1`
     * 
     */
    public Optional<String> availabilityDomain() {
        return Optional.ofNullable(this.availabilityDomain);
    }
    /**
     * @return The OCID of the compute capacity reservation this instance is launched under. When this field contains an empty string or is null, the instance is not currently in a capacity reservation. For more information, see [Capacity Reservations](https://docs.cloud.oracle.com/iaas/Content/Compute/Tasks/reserve-capacity.htm#default).
     * 
     */
    public Optional<String> capacityReservationId() {
        return Optional.ofNullable(this.capacityReservationId);
    }
    /**
     * @return The OCID of the compartment containing images to search
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    public Optional<String> computeClusterId() {
        return Optional.ofNullable(this.computeClusterId);
    }
    /**
     * @return A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }
    public List<GetInstancesFilter> filters() {
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
     * @return The list of instances.
     * 
     */
    public List<GetInstancesInstance> instances() {
        return this.instances;
    }
    /**
     * @return The current state of the instance.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetInstancesResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String availabilityDomain;
        private @Nullable String capacityReservationId;
        private String compartmentId;
        private @Nullable String computeClusterId;
        private @Nullable String displayName;
        private @Nullable List<GetInstancesFilter> filters;
        private String id;
        private List<GetInstancesInstance> instances;
        private @Nullable String state;
        public Builder() {}
        public Builder(GetInstancesResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.availabilityDomain = defaults.availabilityDomain;
    	      this.capacityReservationId = defaults.capacityReservationId;
    	      this.compartmentId = defaults.compartmentId;
    	      this.computeClusterId = defaults.computeClusterId;
    	      this.displayName = defaults.displayName;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.instances = defaults.instances;
    	      this.state = defaults.state;
        }

        @CustomType.Setter
        public Builder availabilityDomain(@Nullable String availabilityDomain) {

            this.availabilityDomain = availabilityDomain;
            return this;
        }
        @CustomType.Setter
        public Builder capacityReservationId(@Nullable String capacityReservationId) {

            this.capacityReservationId = capacityReservationId;
            return this;
        }
        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            if (compartmentId == null) {
              throw new MissingRequiredPropertyException("GetInstancesResult", "compartmentId");
            }
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder computeClusterId(@Nullable String computeClusterId) {

            this.computeClusterId = computeClusterId;
            return this;
        }
        @CustomType.Setter
        public Builder displayName(@Nullable String displayName) {

            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetInstancesFilter> filters) {

            this.filters = filters;
            return this;
        }
        public Builder filters(GetInstancesFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetInstancesResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder instances(List<GetInstancesInstance> instances) {
            if (instances == null) {
              throw new MissingRequiredPropertyException("GetInstancesResult", "instances");
            }
            this.instances = instances;
            return this;
        }
        public Builder instances(GetInstancesInstance... instances) {
            return instances(List.of(instances));
        }
        @CustomType.Setter
        public Builder state(@Nullable String state) {

            this.state = state;
            return this;
        }
        public GetInstancesResult build() {
            final var _resultValue = new GetInstancesResult();
            _resultValue.availabilityDomain = availabilityDomain;
            _resultValue.capacityReservationId = capacityReservationId;
            _resultValue.compartmentId = compartmentId;
            _resultValue.computeClusterId = computeClusterId;
            _resultValue.displayName = displayName;
            _resultValue.filters = filters;
            _resultValue.id = id;
            _resultValue.instances = instances;
            _resultValue.state = state;
            return _resultValue;
        }
    }
}
