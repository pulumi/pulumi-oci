// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Identity.outputs.GetIamWorkRequestsFilter;
import com.pulumi.oci.Identity.outputs.GetIamWorkRequestsIamWorkRequest;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetIamWorkRequestsResult {
    /**
     * @return The OCID of the compartment containing this IAM work request.
     * 
     */
    private final String compartmentId;
    private final @Nullable List<GetIamWorkRequestsFilter> filters;
    /**
     * @return The list of iam_work_requests.
     * 
     */
    private final List<GetIamWorkRequestsIamWorkRequest> iamWorkRequests;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private final String id;
    private final @Nullable String resourceIdentifier;

    @CustomType.Constructor
    private GetIamWorkRequestsResult(
        @CustomType.Parameter("compartmentId") String compartmentId,
        @CustomType.Parameter("filters") @Nullable List<GetIamWorkRequestsFilter> filters,
        @CustomType.Parameter("iamWorkRequests") List<GetIamWorkRequestsIamWorkRequest> iamWorkRequests,
        @CustomType.Parameter("id") String id,
        @CustomType.Parameter("resourceIdentifier") @Nullable String resourceIdentifier) {
        this.compartmentId = compartmentId;
        this.filters = filters;
        this.iamWorkRequests = iamWorkRequests;
        this.id = id;
        this.resourceIdentifier = resourceIdentifier;
    }

    /**
     * @return The OCID of the compartment containing this IAM work request.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    public List<GetIamWorkRequestsFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return The list of iam_work_requests.
     * 
     */
    public List<GetIamWorkRequestsIamWorkRequest> iamWorkRequests() {
        return this.iamWorkRequests;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    public Optional<String> resourceIdentifier() {
        return Optional.ofNullable(this.resourceIdentifier);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetIamWorkRequestsResult defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String compartmentId;
        private @Nullable List<GetIamWorkRequestsFilter> filters;
        private List<GetIamWorkRequestsIamWorkRequest> iamWorkRequests;
        private String id;
        private @Nullable String resourceIdentifier;

        public Builder() {
    	      // Empty
        }

        public Builder(GetIamWorkRequestsResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.filters = defaults.filters;
    	      this.iamWorkRequests = defaults.iamWorkRequests;
    	      this.id = defaults.id;
    	      this.resourceIdentifier = defaults.resourceIdentifier;
        }

        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        public Builder filters(@Nullable List<GetIamWorkRequestsFilter> filters) {
            this.filters = filters;
            return this;
        }
        public Builder filters(GetIamWorkRequestsFilter... filters) {
            return filters(List.of(filters));
        }
        public Builder iamWorkRequests(List<GetIamWorkRequestsIamWorkRequest> iamWorkRequests) {
            this.iamWorkRequests = Objects.requireNonNull(iamWorkRequests);
            return this;
        }
        public Builder iamWorkRequests(GetIamWorkRequestsIamWorkRequest... iamWorkRequests) {
            return iamWorkRequests(List.of(iamWorkRequests));
        }
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        public Builder resourceIdentifier(@Nullable String resourceIdentifier) {
            this.resourceIdentifier = resourceIdentifier;
            return this;
        }        public GetIamWorkRequestsResult build() {
            return new GetIamWorkRequestsResult(compartmentId, filters, iamWorkRequests, id, resourceIdentifier);
        }
    }
}
