// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataIntegration.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.DataIntegration.outputs.GetWorkspaceApplicationsApplicationSummaryCollection;
import com.pulumi.oci.DataIntegration.outputs.GetWorkspaceApplicationsFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetWorkspaceApplicationsResult {
    /**
     * @return The list of application_summary_collection.
     * 
     */
    private List<GetWorkspaceApplicationsApplicationSummaryCollection> applicationSummaryCollections;
    private @Nullable List<String> fields;
    private @Nullable List<GetWorkspaceApplicationsFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return Value can only contain upper case letters, underscore and numbers. It should begin with upper case letter or underscore. The value can be modified.
     * 
     */
    private @Nullable List<String> identifiers;
    /**
     * @return Free form text without any restriction on permitted characters. Name can have letters, numbers, and special characters. The value is editable and is restricted to 1000 characters.
     * 
     */
    private @Nullable String name;
    private @Nullable String nameContains;
    /**
     * @return The OCID of the workspace containing the application. This allows cross workspace deployment to publish an application from a different workspace into the current workspace specified in this operation.
     * 
     */
    private String workspaceId;

    private GetWorkspaceApplicationsResult() {}
    /**
     * @return The list of application_summary_collection.
     * 
     */
    public List<GetWorkspaceApplicationsApplicationSummaryCollection> applicationSummaryCollections() {
        return this.applicationSummaryCollections;
    }
    public List<String> fields() {
        return this.fields == null ? List.of() : this.fields;
    }
    public List<GetWorkspaceApplicationsFilter> filters() {
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
     * @return Value can only contain upper case letters, underscore and numbers. It should begin with upper case letter or underscore. The value can be modified.
     * 
     */
    public List<String> identifiers() {
        return this.identifiers == null ? List.of() : this.identifiers;
    }
    /**
     * @return Free form text without any restriction on permitted characters. Name can have letters, numbers, and special characters. The value is editable and is restricted to 1000 characters.
     * 
     */
    public Optional<String> name() {
        return Optional.ofNullable(this.name);
    }
    public Optional<String> nameContains() {
        return Optional.ofNullable(this.nameContains);
    }
    /**
     * @return The OCID of the workspace containing the application. This allows cross workspace deployment to publish an application from a different workspace into the current workspace specified in this operation.
     * 
     */
    public String workspaceId() {
        return this.workspaceId;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetWorkspaceApplicationsResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetWorkspaceApplicationsApplicationSummaryCollection> applicationSummaryCollections;
        private @Nullable List<String> fields;
        private @Nullable List<GetWorkspaceApplicationsFilter> filters;
        private String id;
        private @Nullable List<String> identifiers;
        private @Nullable String name;
        private @Nullable String nameContains;
        private String workspaceId;
        public Builder() {}
        public Builder(GetWorkspaceApplicationsResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.applicationSummaryCollections = defaults.applicationSummaryCollections;
    	      this.fields = defaults.fields;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.identifiers = defaults.identifiers;
    	      this.name = defaults.name;
    	      this.nameContains = defaults.nameContains;
    	      this.workspaceId = defaults.workspaceId;
        }

        @CustomType.Setter
        public Builder applicationSummaryCollections(List<GetWorkspaceApplicationsApplicationSummaryCollection> applicationSummaryCollections) {
            if (applicationSummaryCollections == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceApplicationsResult", "applicationSummaryCollections");
            }
            this.applicationSummaryCollections = applicationSummaryCollections;
            return this;
        }
        public Builder applicationSummaryCollections(GetWorkspaceApplicationsApplicationSummaryCollection... applicationSummaryCollections) {
            return applicationSummaryCollections(List.of(applicationSummaryCollections));
        }
        @CustomType.Setter
        public Builder fields(@Nullable List<String> fields) {

            this.fields = fields;
            return this;
        }
        public Builder fields(String... fields) {
            return fields(List.of(fields));
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetWorkspaceApplicationsFilter> filters) {

            this.filters = filters;
            return this;
        }
        public Builder filters(GetWorkspaceApplicationsFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceApplicationsResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder identifiers(@Nullable List<String> identifiers) {

            this.identifiers = identifiers;
            return this;
        }
        public Builder identifiers(String... identifiers) {
            return identifiers(List.of(identifiers));
        }
        @CustomType.Setter
        public Builder name(@Nullable String name) {

            this.name = name;
            return this;
        }
        @CustomType.Setter
        public Builder nameContains(@Nullable String nameContains) {

            this.nameContains = nameContains;
            return this;
        }
        @CustomType.Setter
        public Builder workspaceId(String workspaceId) {
            if (workspaceId == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceApplicationsResult", "workspaceId");
            }
            this.workspaceId = workspaceId;
            return this;
        }
        public GetWorkspaceApplicationsResult build() {
            final var _resultValue = new GetWorkspaceApplicationsResult();
            _resultValue.applicationSummaryCollections = applicationSummaryCollections;
            _resultValue.fields = fields;
            _resultValue.filters = filters;
            _resultValue.id = id;
            _resultValue.identifiers = identifiers;
            _resultValue.name = name;
            _resultValue.nameContains = nameContains;
            _resultValue.workspaceId = workspaceId;
            return _resultValue;
        }
    }
}
