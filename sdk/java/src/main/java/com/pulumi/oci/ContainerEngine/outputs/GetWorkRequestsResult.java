// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ContainerEngine.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.ContainerEngine.outputs.GetWorkRequestsFilter;
import com.pulumi.oci.ContainerEngine.outputs.GetWorkRequestsWorkRequest;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetWorkRequestsResult {
    private final @Nullable String clusterId;
    /**
     * @return The OCID of the compartment in which the work request exists.
     * 
     */
    private final String compartmentId;
    private final @Nullable List<GetWorkRequestsFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private final String id;
    private final @Nullable String resourceId;
    private final @Nullable String resourceType;
    /**
     * @return The current status of the work request.
     * 
     */
    private final @Nullable List<String> statuses;
    /**
     * @return The list of work_requests.
     * 
     */
    private final List<GetWorkRequestsWorkRequest> workRequests;

    @CustomType.Constructor
    private GetWorkRequestsResult(
        @CustomType.Parameter("clusterId") @Nullable String clusterId,
        @CustomType.Parameter("compartmentId") String compartmentId,
        @CustomType.Parameter("filters") @Nullable List<GetWorkRequestsFilter> filters,
        @CustomType.Parameter("id") String id,
        @CustomType.Parameter("resourceId") @Nullable String resourceId,
        @CustomType.Parameter("resourceType") @Nullable String resourceType,
        @CustomType.Parameter("statuses") @Nullable List<String> statuses,
        @CustomType.Parameter("workRequests") List<GetWorkRequestsWorkRequest> workRequests) {
        this.clusterId = clusterId;
        this.compartmentId = compartmentId;
        this.filters = filters;
        this.id = id;
        this.resourceId = resourceId;
        this.resourceType = resourceType;
        this.statuses = statuses;
        this.workRequests = workRequests;
    }

    public Optional<String> clusterId() {
        return Optional.ofNullable(this.clusterId);
    }
    /**
     * @return The OCID of the compartment in which the work request exists.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    public List<GetWorkRequestsFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    public Optional<String> resourceId() {
        return Optional.ofNullable(this.resourceId);
    }
    public Optional<String> resourceType() {
        return Optional.ofNullable(this.resourceType);
    }
    /**
     * @return The current status of the work request.
     * 
     */
    public List<String> statuses() {
        return this.statuses == null ? List.of() : this.statuses;
    }
    /**
     * @return The list of work_requests.
     * 
     */
    public List<GetWorkRequestsWorkRequest> workRequests() {
        return this.workRequests;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetWorkRequestsResult defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private @Nullable String clusterId;
        private String compartmentId;
        private @Nullable List<GetWorkRequestsFilter> filters;
        private String id;
        private @Nullable String resourceId;
        private @Nullable String resourceType;
        private @Nullable List<String> statuses;
        private List<GetWorkRequestsWorkRequest> workRequests;

        public Builder() {
    	      // Empty
        }

        public Builder(GetWorkRequestsResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.clusterId = defaults.clusterId;
    	      this.compartmentId = defaults.compartmentId;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.resourceId = defaults.resourceId;
    	      this.resourceType = defaults.resourceType;
    	      this.statuses = defaults.statuses;
    	      this.workRequests = defaults.workRequests;
        }

        public Builder clusterId(@Nullable String clusterId) {
            this.clusterId = clusterId;
            return this;
        }
        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        public Builder filters(@Nullable List<GetWorkRequestsFilter> filters) {
            this.filters = filters;
            return this;
        }
        public Builder filters(GetWorkRequestsFilter... filters) {
            return filters(List.of(filters));
        }
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        public Builder resourceId(@Nullable String resourceId) {
            this.resourceId = resourceId;
            return this;
        }
        public Builder resourceType(@Nullable String resourceType) {
            this.resourceType = resourceType;
            return this;
        }
        public Builder statuses(@Nullable List<String> statuses) {
            this.statuses = statuses;
            return this;
        }
        public Builder statuses(String... statuses) {
            return statuses(List.of(statuses));
        }
        public Builder workRequests(List<GetWorkRequestsWorkRequest> workRequests) {
            this.workRequests = Objects.requireNonNull(workRequests);
            return this;
        }
        public Builder workRequests(GetWorkRequestsWorkRequest... workRequests) {
            return workRequests(List.of(workRequests));
        }        public GetWorkRequestsResult build() {
            return new GetWorkRequestsResult(clusterId, compartmentId, filters, id, resourceId, resourceType, statuses, workRequests);
        }
    }
}
