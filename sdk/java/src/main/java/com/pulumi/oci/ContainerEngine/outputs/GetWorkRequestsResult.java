// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ContainerEngine.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.ContainerEngine.outputs.GetWorkRequestsFilter;
import com.pulumi.oci.ContainerEngine.outputs.GetWorkRequestsWorkRequest;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetWorkRequestsResult {
    private @Nullable String clusterId;
    /**
     * @return The OCID of the compartment in which the work request exists.
     * 
     */
    private String compartmentId;
    private @Nullable List<GetWorkRequestsFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    private @Nullable String resourceId;
    private @Nullable String resourceType;
    /**
     * @return The current status of the work request.
     * 
     */
    private @Nullable List<String> statuses;
    /**
     * @return The list of work_requests.
     * 
     */
    private List<GetWorkRequestsWorkRequest> workRequests;

    private GetWorkRequestsResult() {}
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
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String clusterId;
        private String compartmentId;
        private @Nullable List<GetWorkRequestsFilter> filters;
        private String id;
        private @Nullable String resourceId;
        private @Nullable String resourceType;
        private @Nullable List<String> statuses;
        private List<GetWorkRequestsWorkRequest> workRequests;
        public Builder() {}
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

        @CustomType.Setter
        public Builder clusterId(@Nullable String clusterId) {

            this.clusterId = clusterId;
            return this;
        }
        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            if (compartmentId == null) {
              throw new MissingRequiredPropertyException("GetWorkRequestsResult", "compartmentId");
            }
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetWorkRequestsFilter> filters) {

            this.filters = filters;
            return this;
        }
        public Builder filters(GetWorkRequestsFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetWorkRequestsResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder resourceId(@Nullable String resourceId) {

            this.resourceId = resourceId;
            return this;
        }
        @CustomType.Setter
        public Builder resourceType(@Nullable String resourceType) {

            this.resourceType = resourceType;
            return this;
        }
        @CustomType.Setter
        public Builder statuses(@Nullable List<String> statuses) {

            this.statuses = statuses;
            return this;
        }
        public Builder statuses(String... statuses) {
            return statuses(List.of(statuses));
        }
        @CustomType.Setter
        public Builder workRequests(List<GetWorkRequestsWorkRequest> workRequests) {
            if (workRequests == null) {
              throw new MissingRequiredPropertyException("GetWorkRequestsResult", "workRequests");
            }
            this.workRequests = workRequests;
            return this;
        }
        public Builder workRequests(GetWorkRequestsWorkRequest... workRequests) {
            return workRequests(List.of(workRequests));
        }
        public GetWorkRequestsResult build() {
            final var _resultValue = new GetWorkRequestsResult();
            _resultValue.clusterId = clusterId;
            _resultValue.compartmentId = compartmentId;
            _resultValue.filters = filters;
            _resultValue.id = id;
            _resultValue.resourceId = resourceId;
            _resultValue.resourceType = resourceType;
            _resultValue.statuses = statuses;
            _resultValue.workRequests = workRequests;
            return _resultValue;
        }
    }
}
