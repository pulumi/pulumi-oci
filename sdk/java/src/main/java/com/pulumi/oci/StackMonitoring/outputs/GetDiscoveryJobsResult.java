// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.StackMonitoring.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.StackMonitoring.outputs.GetDiscoveryJobsDiscoveryJobCollection;
import com.pulumi.oci.StackMonitoring.outputs.GetDiscoveryJobsFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetDiscoveryJobsResult {
    /**
     * @return The OCID of the Compartment
     * 
     */
    private final String compartmentId;
    /**
     * @return The list of discovery_job_collection.
     * 
     */
    private final List<GetDiscoveryJobsDiscoveryJobCollection> discoveryJobCollections;
    private final @Nullable List<GetDiscoveryJobsFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private final String id;
    private final @Nullable String name;

    @CustomType.Constructor
    private GetDiscoveryJobsResult(
        @CustomType.Parameter("compartmentId") String compartmentId,
        @CustomType.Parameter("discoveryJobCollections") List<GetDiscoveryJobsDiscoveryJobCollection> discoveryJobCollections,
        @CustomType.Parameter("filters") @Nullable List<GetDiscoveryJobsFilter> filters,
        @CustomType.Parameter("id") String id,
        @CustomType.Parameter("name") @Nullable String name) {
        this.compartmentId = compartmentId;
        this.discoveryJobCollections = discoveryJobCollections;
        this.filters = filters;
        this.id = id;
        this.name = name;
    }

    /**
     * @return The OCID of the Compartment
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return The list of discovery_job_collection.
     * 
     */
    public List<GetDiscoveryJobsDiscoveryJobCollection> discoveryJobCollections() {
        return this.discoveryJobCollections;
    }
    public List<GetDiscoveryJobsFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    public Optional<String> name() {
        return Optional.ofNullable(this.name);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDiscoveryJobsResult defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String compartmentId;
        private List<GetDiscoveryJobsDiscoveryJobCollection> discoveryJobCollections;
        private @Nullable List<GetDiscoveryJobsFilter> filters;
        private String id;
        private @Nullable String name;

        public Builder() {
    	      // Empty
        }

        public Builder(GetDiscoveryJobsResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.discoveryJobCollections = defaults.discoveryJobCollections;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.name = defaults.name;
        }

        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        public Builder discoveryJobCollections(List<GetDiscoveryJobsDiscoveryJobCollection> discoveryJobCollections) {
            this.discoveryJobCollections = Objects.requireNonNull(discoveryJobCollections);
            return this;
        }
        public Builder discoveryJobCollections(GetDiscoveryJobsDiscoveryJobCollection... discoveryJobCollections) {
            return discoveryJobCollections(List.of(discoveryJobCollections));
        }
        public Builder filters(@Nullable List<GetDiscoveryJobsFilter> filters) {
            this.filters = filters;
            return this;
        }
        public Builder filters(GetDiscoveryJobsFilter... filters) {
            return filters(List.of(filters));
        }
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        public Builder name(@Nullable String name) {
            this.name = name;
            return this;
        }        public GetDiscoveryJobsResult build() {
            return new GetDiscoveryJobsResult(compartmentId, discoveryJobCollections, filters, id, name);
        }
    }
}
