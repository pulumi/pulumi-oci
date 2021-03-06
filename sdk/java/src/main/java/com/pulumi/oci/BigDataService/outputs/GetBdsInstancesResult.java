// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.BigDataService.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.BigDataService.outputs.GetBdsInstancesBdsInstance;
import com.pulumi.oci.BigDataService.outputs.GetBdsInstancesFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetBdsInstancesResult {
    /**
     * @return The list of bds_instances.
     * 
     */
    private final List<GetBdsInstancesBdsInstance> bdsInstances;
    /**
     * @return The OCID of the compartment.
     * 
     */
    private final String compartmentId;
    /**
     * @return The name of the node.
     * 
     */
    private final @Nullable String displayName;
    private final @Nullable List<GetBdsInstancesFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private final String id;
    /**
     * @return The state of the cluster.
     * 
     */
    private final @Nullable String state;

    @CustomType.Constructor
    private GetBdsInstancesResult(
        @CustomType.Parameter("bdsInstances") List<GetBdsInstancesBdsInstance> bdsInstances,
        @CustomType.Parameter("compartmentId") String compartmentId,
        @CustomType.Parameter("displayName") @Nullable String displayName,
        @CustomType.Parameter("filters") @Nullable List<GetBdsInstancesFilter> filters,
        @CustomType.Parameter("id") String id,
        @CustomType.Parameter("state") @Nullable String state) {
        this.bdsInstances = bdsInstances;
        this.compartmentId = compartmentId;
        this.displayName = displayName;
        this.filters = filters;
        this.id = id;
        this.state = state;
    }

    /**
     * @return The list of bds_instances.
     * 
     */
    public List<GetBdsInstancesBdsInstance> bdsInstances() {
        return this.bdsInstances;
    }
    /**
     * @return The OCID of the compartment.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return The name of the node.
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }
    public List<GetBdsInstancesFilter> filters() {
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
     * @return The state of the cluster.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetBdsInstancesResult defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private List<GetBdsInstancesBdsInstance> bdsInstances;
        private String compartmentId;
        private @Nullable String displayName;
        private @Nullable List<GetBdsInstancesFilter> filters;
        private String id;
        private @Nullable String state;

        public Builder() {
    	      // Empty
        }

        public Builder(GetBdsInstancesResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.bdsInstances = defaults.bdsInstances;
    	      this.compartmentId = defaults.compartmentId;
    	      this.displayName = defaults.displayName;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.state = defaults.state;
        }

        public Builder bdsInstances(List<GetBdsInstancesBdsInstance> bdsInstances) {
            this.bdsInstances = Objects.requireNonNull(bdsInstances);
            return this;
        }
        public Builder bdsInstances(GetBdsInstancesBdsInstance... bdsInstances) {
            return bdsInstances(List.of(bdsInstances));
        }
        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        public Builder displayName(@Nullable String displayName) {
            this.displayName = displayName;
            return this;
        }
        public Builder filters(@Nullable List<GetBdsInstancesFilter> filters) {
            this.filters = filters;
            return this;
        }
        public Builder filters(GetBdsInstancesFilter... filters) {
            return filters(List.of(filters));
        }
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        public Builder state(@Nullable String state) {
            this.state = state;
            return this;
        }        public GetBdsInstancesResult build() {
            return new GetBdsInstancesResult(bdsInstances, compartmentId, displayName, filters, id, state);
        }
    }
}
