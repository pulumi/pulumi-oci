// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataSafe.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DataSafe.outputs.GetDiscoveryJobsResultsDiscoveryJobResultCollection;
import com.pulumi.oci.DataSafe.outputs.GetDiscoveryJobsResultsFilter;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetDiscoveryJobsResultsResult {
    /**
     * @return The name of the sensitive column.
     * 
     */
    private @Nullable List<String> columnNames;
    private String discoveryJobId;
    /**
     * @return The list of discovery_job_result_collection.
     * 
     */
    private List<GetDiscoveryJobsResultsDiscoveryJobResultCollection> discoveryJobResultCollections;
    /**
     * @return The type of the discovery result. It can be one of the following three types: NEW: A new sensitive column in the target database that is not in the sensitive data model. DELETED: A column that is present in the sensitive data model but has been deleted from the target database. MODIFIED: A column that is present in the target database as well as the sensitive data model but some of its attributes have been modified.
     * 
     */
    private @Nullable String discoveryType;
    private @Nullable List<GetDiscoveryJobsResultsFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return Indicates if the discovery result has been processed. You can update this attribute using the PatchDiscoveryJobResults operation to track whether the discovery result has already been processed and applied to the sensitive data model.
     * 
     */
    private @Nullable Boolean isResultApplied;
    /**
     * @return The database object that contains the sensitive column.
     * 
     */
    private @Nullable List<String> objects;
    /**
     * @return Specifies how to process the discovery result. It&#39;s set to NONE by default. Use the PatchDiscoveryJobResults operation to update this attribute. You can choose one of the following options: ACCEPT: To accept the discovery result and update the sensitive data model to reflect the changes. REJECT: To reject the discovery result so that it doesn&#39;t change the sensitive data model. INVALIDATE: To invalidate a newly discovered column. It adds the column to the sensitive data model but marks it as invalid. It helps track false positives and ensure that they aren&#39;t reported by future discovery jobs. After specifying the planned action, you can use the ApplyDiscoveryJobResults operation to automatically process the discovery results.
     * 
     */
    private @Nullable String plannedAction;
    /**
     * @return The database schema that contains the sensitive column.
     * 
     */
    private @Nullable List<String> schemaNames;

    private GetDiscoveryJobsResultsResult() {}
    /**
     * @return The name of the sensitive column.
     * 
     */
    public List<String> columnNames() {
        return this.columnNames == null ? List.of() : this.columnNames;
    }
    public String discoveryJobId() {
        return this.discoveryJobId;
    }
    /**
     * @return The list of discovery_job_result_collection.
     * 
     */
    public List<GetDiscoveryJobsResultsDiscoveryJobResultCollection> discoveryJobResultCollections() {
        return this.discoveryJobResultCollections;
    }
    /**
     * @return The type of the discovery result. It can be one of the following three types: NEW: A new sensitive column in the target database that is not in the sensitive data model. DELETED: A column that is present in the sensitive data model but has been deleted from the target database. MODIFIED: A column that is present in the target database as well as the sensitive data model but some of its attributes have been modified.
     * 
     */
    public Optional<String> discoveryType() {
        return Optional.ofNullable(this.discoveryType);
    }
    public List<GetDiscoveryJobsResultsFilter> filters() {
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
     * @return Indicates if the discovery result has been processed. You can update this attribute using the PatchDiscoveryJobResults operation to track whether the discovery result has already been processed and applied to the sensitive data model.
     * 
     */
    public Optional<Boolean> isResultApplied() {
        return Optional.ofNullable(this.isResultApplied);
    }
    /**
     * @return The database object that contains the sensitive column.
     * 
     */
    public List<String> objects() {
        return this.objects == null ? List.of() : this.objects;
    }
    /**
     * @return Specifies how to process the discovery result. It&#39;s set to NONE by default. Use the PatchDiscoveryJobResults operation to update this attribute. You can choose one of the following options: ACCEPT: To accept the discovery result and update the sensitive data model to reflect the changes. REJECT: To reject the discovery result so that it doesn&#39;t change the sensitive data model. INVALIDATE: To invalidate a newly discovered column. It adds the column to the sensitive data model but marks it as invalid. It helps track false positives and ensure that they aren&#39;t reported by future discovery jobs. After specifying the planned action, you can use the ApplyDiscoveryJobResults operation to automatically process the discovery results.
     * 
     */
    public Optional<String> plannedAction() {
        return Optional.ofNullable(this.plannedAction);
    }
    /**
     * @return The database schema that contains the sensitive column.
     * 
     */
    public List<String> schemaNames() {
        return this.schemaNames == null ? List.of() : this.schemaNames;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDiscoveryJobsResultsResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable List<String> columnNames;
        private String discoveryJobId;
        private List<GetDiscoveryJobsResultsDiscoveryJobResultCollection> discoveryJobResultCollections;
        private @Nullable String discoveryType;
        private @Nullable List<GetDiscoveryJobsResultsFilter> filters;
        private String id;
        private @Nullable Boolean isResultApplied;
        private @Nullable List<String> objects;
        private @Nullable String plannedAction;
        private @Nullable List<String> schemaNames;
        public Builder() {}
        public Builder(GetDiscoveryJobsResultsResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.columnNames = defaults.columnNames;
    	      this.discoveryJobId = defaults.discoveryJobId;
    	      this.discoveryJobResultCollections = defaults.discoveryJobResultCollections;
    	      this.discoveryType = defaults.discoveryType;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.isResultApplied = defaults.isResultApplied;
    	      this.objects = defaults.objects;
    	      this.plannedAction = defaults.plannedAction;
    	      this.schemaNames = defaults.schemaNames;
        }

        @CustomType.Setter
        public Builder columnNames(@Nullable List<String> columnNames) {
            this.columnNames = columnNames;
            return this;
        }
        public Builder columnNames(String... columnNames) {
            return columnNames(List.of(columnNames));
        }
        @CustomType.Setter
        public Builder discoveryJobId(String discoveryJobId) {
            this.discoveryJobId = Objects.requireNonNull(discoveryJobId);
            return this;
        }
        @CustomType.Setter
        public Builder discoveryJobResultCollections(List<GetDiscoveryJobsResultsDiscoveryJobResultCollection> discoveryJobResultCollections) {
            this.discoveryJobResultCollections = Objects.requireNonNull(discoveryJobResultCollections);
            return this;
        }
        public Builder discoveryJobResultCollections(GetDiscoveryJobsResultsDiscoveryJobResultCollection... discoveryJobResultCollections) {
            return discoveryJobResultCollections(List.of(discoveryJobResultCollections));
        }
        @CustomType.Setter
        public Builder discoveryType(@Nullable String discoveryType) {
            this.discoveryType = discoveryType;
            return this;
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetDiscoveryJobsResultsFilter> filters) {
            this.filters = filters;
            return this;
        }
        public Builder filters(GetDiscoveryJobsResultsFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        @CustomType.Setter
        public Builder isResultApplied(@Nullable Boolean isResultApplied) {
            this.isResultApplied = isResultApplied;
            return this;
        }
        @CustomType.Setter
        public Builder objects(@Nullable List<String> objects) {
            this.objects = objects;
            return this;
        }
        public Builder objects(String... objects) {
            return objects(List.of(objects));
        }
        @CustomType.Setter
        public Builder plannedAction(@Nullable String plannedAction) {
            this.plannedAction = plannedAction;
            return this;
        }
        @CustomType.Setter
        public Builder schemaNames(@Nullable List<String> schemaNames) {
            this.schemaNames = schemaNames;
            return this;
        }
        public Builder schemaNames(String... schemaNames) {
            return schemaNames(List.of(schemaNames));
        }
        public GetDiscoveryJobsResultsResult build() {
            final var o = new GetDiscoveryJobsResultsResult();
            o.columnNames = columnNames;
            o.discoveryJobId = discoveryJobId;
            o.discoveryJobResultCollections = discoveryJobResultCollections;
            o.discoveryType = discoveryType;
            o.filters = filters;
            o.id = id;
            o.isResultApplied = isResultApplied;
            o.objects = objects;
            o.plannedAction = plannedAction;
            o.schemaNames = schemaNames;
            return o;
        }
    }
}