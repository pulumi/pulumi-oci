// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ContainerEngine.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.ContainerEngine.outputs.GetWorkRequestLogEntriesFilter;
import com.pulumi.oci.ContainerEngine.outputs.GetWorkRequestLogEntriesWorkRequestLogEntry;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import javax.annotation.Nullable;

@CustomType
public final class GetWorkRequestLogEntriesResult {
    private String compartmentId;
    private @Nullable List<GetWorkRequestLogEntriesFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    private String workRequestId;
    /**
     * @return The list of work_request_log_entries.
     * 
     */
    private List<GetWorkRequestLogEntriesWorkRequestLogEntry> workRequestLogEntries;

    private GetWorkRequestLogEntriesResult() {}
    public String compartmentId() {
        return this.compartmentId;
    }
    public List<GetWorkRequestLogEntriesFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    public String workRequestId() {
        return this.workRequestId;
    }
    /**
     * @return The list of work_request_log_entries.
     * 
     */
    public List<GetWorkRequestLogEntriesWorkRequestLogEntry> workRequestLogEntries() {
        return this.workRequestLogEntries;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetWorkRequestLogEntriesResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String compartmentId;
        private @Nullable List<GetWorkRequestLogEntriesFilter> filters;
        private String id;
        private String workRequestId;
        private List<GetWorkRequestLogEntriesWorkRequestLogEntry> workRequestLogEntries;
        public Builder() {}
        public Builder(GetWorkRequestLogEntriesResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.workRequestId = defaults.workRequestId;
    	      this.workRequestLogEntries = defaults.workRequestLogEntries;
        }

        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetWorkRequestLogEntriesFilter> filters) {
            this.filters = filters;
            return this;
        }
        public Builder filters(GetWorkRequestLogEntriesFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        @CustomType.Setter
        public Builder workRequestId(String workRequestId) {
            this.workRequestId = Objects.requireNonNull(workRequestId);
            return this;
        }
        @CustomType.Setter
        public Builder workRequestLogEntries(List<GetWorkRequestLogEntriesWorkRequestLogEntry> workRequestLogEntries) {
            this.workRequestLogEntries = Objects.requireNonNull(workRequestLogEntries);
            return this;
        }
        public Builder workRequestLogEntries(GetWorkRequestLogEntriesWorkRequestLogEntry... workRequestLogEntries) {
            return workRequestLogEntries(List.of(workRequestLogEntries));
        }
        public GetWorkRequestLogEntriesResult build() {
            final var o = new GetWorkRequestLogEntriesResult();
            o.compartmentId = compartmentId;
            o.filters = filters;
            o.id = id;
            o.workRequestId = workRequestId;
            o.workRequestLogEntries = workRequestLogEntries;
            return o;
        }
    }
}