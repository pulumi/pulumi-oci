// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ContainerEngine.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.ContainerEngine.outputs.GetWorkRequestErrorsFilter;
import com.pulumi.oci.ContainerEngine.outputs.GetWorkRequestErrorsWorkRequestError;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import javax.annotation.Nullable;

@CustomType
public final class GetWorkRequestErrorsResult {
    private String compartmentId;
    private @Nullable List<GetWorkRequestErrorsFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return The list of work_request_errors.
     * 
     */
    private List<GetWorkRequestErrorsWorkRequestError> workRequestErrors;
    private String workRequestId;

    private GetWorkRequestErrorsResult() {}
    public String compartmentId() {
        return this.compartmentId;
    }
    public List<GetWorkRequestErrorsFilter> filters() {
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
     * @return The list of work_request_errors.
     * 
     */
    public List<GetWorkRequestErrorsWorkRequestError> workRequestErrors() {
        return this.workRequestErrors;
    }
    public String workRequestId() {
        return this.workRequestId;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetWorkRequestErrorsResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String compartmentId;
        private @Nullable List<GetWorkRequestErrorsFilter> filters;
        private String id;
        private List<GetWorkRequestErrorsWorkRequestError> workRequestErrors;
        private String workRequestId;
        public Builder() {}
        public Builder(GetWorkRequestErrorsResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.workRequestErrors = defaults.workRequestErrors;
    	      this.workRequestId = defaults.workRequestId;
        }

        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetWorkRequestErrorsFilter> filters) {
            this.filters = filters;
            return this;
        }
        public Builder filters(GetWorkRequestErrorsFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        @CustomType.Setter
        public Builder workRequestErrors(List<GetWorkRequestErrorsWorkRequestError> workRequestErrors) {
            this.workRequestErrors = Objects.requireNonNull(workRequestErrors);
            return this;
        }
        public Builder workRequestErrors(GetWorkRequestErrorsWorkRequestError... workRequestErrors) {
            return workRequestErrors(List.of(workRequestErrors));
        }
        @CustomType.Setter
        public Builder workRequestId(String workRequestId) {
            this.workRequestId = Objects.requireNonNull(workRequestId);
            return this;
        }
        public GetWorkRequestErrorsResult build() {
            final var o = new GetWorkRequestErrorsResult();
            o.compartmentId = compartmentId;
            o.filters = filters;
            o.id = id;
            o.workRequestErrors = workRequestErrors;
            o.workRequestId = workRequestId;
            return o;
        }
    }
}