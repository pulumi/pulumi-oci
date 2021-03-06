// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Oce.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Oce.outputs.GetOceInstancesFilter;
import com.pulumi.oci.Oce.outputs.GetOceInstancesOceInstance;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetOceInstancesResult {
    /**
     * @return Compartment Identifier
     * 
     */
    private final String compartmentId;
    private final @Nullable String displayName;
    private final @Nullable List<GetOceInstancesFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private final String id;
    /**
     * @return The list of oce_instances.
     * 
     */
    private final List<GetOceInstancesOceInstance> oceInstances;
    /**
     * @return The current state of the instance lifecycle.
     * 
     */
    private final @Nullable String state;
    /**
     * @return Tenancy Identifier
     * 
     */
    private final @Nullable String tenancyId;

    @CustomType.Constructor
    private GetOceInstancesResult(
        @CustomType.Parameter("compartmentId") String compartmentId,
        @CustomType.Parameter("displayName") @Nullable String displayName,
        @CustomType.Parameter("filters") @Nullable List<GetOceInstancesFilter> filters,
        @CustomType.Parameter("id") String id,
        @CustomType.Parameter("oceInstances") List<GetOceInstancesOceInstance> oceInstances,
        @CustomType.Parameter("state") @Nullable String state,
        @CustomType.Parameter("tenancyId") @Nullable String tenancyId) {
        this.compartmentId = compartmentId;
        this.displayName = displayName;
        this.filters = filters;
        this.id = id;
        this.oceInstances = oceInstances;
        this.state = state;
        this.tenancyId = tenancyId;
    }

    /**
     * @return Compartment Identifier
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }
    public List<GetOceInstancesFilter> filters() {
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
     * @return The list of oce_instances.
     * 
     */
    public List<GetOceInstancesOceInstance> oceInstances() {
        return this.oceInstances;
    }
    /**
     * @return The current state of the instance lifecycle.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }
    /**
     * @return Tenancy Identifier
     * 
     */
    public Optional<String> tenancyId() {
        return Optional.ofNullable(this.tenancyId);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetOceInstancesResult defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String compartmentId;
        private @Nullable String displayName;
        private @Nullable List<GetOceInstancesFilter> filters;
        private String id;
        private List<GetOceInstancesOceInstance> oceInstances;
        private @Nullable String state;
        private @Nullable String tenancyId;

        public Builder() {
    	      // Empty
        }

        public Builder(GetOceInstancesResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.displayName = defaults.displayName;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.oceInstances = defaults.oceInstances;
    	      this.state = defaults.state;
    	      this.tenancyId = defaults.tenancyId;
        }

        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        public Builder displayName(@Nullable String displayName) {
            this.displayName = displayName;
            return this;
        }
        public Builder filters(@Nullable List<GetOceInstancesFilter> filters) {
            this.filters = filters;
            return this;
        }
        public Builder filters(GetOceInstancesFilter... filters) {
            return filters(List.of(filters));
        }
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        public Builder oceInstances(List<GetOceInstancesOceInstance> oceInstances) {
            this.oceInstances = Objects.requireNonNull(oceInstances);
            return this;
        }
        public Builder oceInstances(GetOceInstancesOceInstance... oceInstances) {
            return oceInstances(List.of(oceInstances));
        }
        public Builder state(@Nullable String state) {
            this.state = state;
            return this;
        }
        public Builder tenancyId(@Nullable String tenancyId) {
            this.tenancyId = tenancyId;
            return this;
        }        public GetOceInstancesResult build() {
            return new GetOceInstancesResult(compartmentId, displayName, filters, id, oceInstances, state, tenancyId);
        }
    }
}
