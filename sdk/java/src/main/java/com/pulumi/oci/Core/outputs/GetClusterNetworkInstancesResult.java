// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Core.outputs.GetClusterNetworkInstancesFilter;
import com.pulumi.oci.Core.outputs.GetClusterNetworkInstancesInstance;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetClusterNetworkInstancesResult {
    private String clusterNetworkId;
    /**
     * @return The OCID of the compartment that contains the instance.
     * 
     */
    private String compartmentId;
    /**
     * @return A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    private @Nullable String displayName;
    private @Nullable List<GetClusterNetworkInstancesFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return The list of instances.
     * 
     */
    private List<GetClusterNetworkInstancesInstance> instances;

    private GetClusterNetworkInstancesResult() {}
    public String clusterNetworkId() {
        return this.clusterNetworkId;
    }
    /**
     * @return The OCID of the compartment that contains the instance.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }
    public List<GetClusterNetworkInstancesFilter> filters() {
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
    public List<GetClusterNetworkInstancesInstance> instances() {
        return this.instances;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetClusterNetworkInstancesResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String clusterNetworkId;
        private String compartmentId;
        private @Nullable String displayName;
        private @Nullable List<GetClusterNetworkInstancesFilter> filters;
        private String id;
        private List<GetClusterNetworkInstancesInstance> instances;
        public Builder() {}
        public Builder(GetClusterNetworkInstancesResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.clusterNetworkId = defaults.clusterNetworkId;
    	      this.compartmentId = defaults.compartmentId;
    	      this.displayName = defaults.displayName;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.instances = defaults.instances;
        }

        @CustomType.Setter
        public Builder clusterNetworkId(String clusterNetworkId) {
            this.clusterNetworkId = Objects.requireNonNull(clusterNetworkId);
            return this;
        }
        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        @CustomType.Setter
        public Builder displayName(@Nullable String displayName) {
            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetClusterNetworkInstancesFilter> filters) {
            this.filters = filters;
            return this;
        }
        public Builder filters(GetClusterNetworkInstancesFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        @CustomType.Setter
        public Builder instances(List<GetClusterNetworkInstancesInstance> instances) {
            this.instances = Objects.requireNonNull(instances);
            return this;
        }
        public Builder instances(GetClusterNetworkInstancesInstance... instances) {
            return instances(List.of(instances));
        }
        public GetClusterNetworkInstancesResult build() {
            final var o = new GetClusterNetworkInstancesResult();
            o.clusterNetworkId = clusterNetworkId;
            o.compartmentId = compartmentId;
            o.displayName = displayName;
            o.filters = filters;
            o.id = id;
            o.instances = instances;
            return o;
        }
    }
}