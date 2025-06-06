// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.LogAnalytics.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.LogAnalytics.outputs.GetNamespaceScheduledTasksFilter;
import com.pulumi.oci.LogAnalytics.outputs.GetNamespaceScheduledTasksScheduledTaskCollection;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetNamespaceScheduledTasksResult {
    /**
     * @return Compartment Identifier [OCID] (https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    private String compartmentId;
    /**
     * @return A user-friendly name that is changeable and that does not have to be unique. Format: a leading alphanumeric, followed by zero or more alphanumerics, underscores, spaces, backslashes, or hyphens in any order). No trailing spaces allowed.
     * 
     */
    private @Nullable String displayName;
    private @Nullable List<GetNamespaceScheduledTasksFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    private String namespace;
    /**
     * @return The list of scheduled_task_collection.
     * 
     */
    private List<GetNamespaceScheduledTasksScheduledTaskCollection> scheduledTaskCollections;
    private @Nullable String targetService;
    /**
     * @return Task type.
     * 
     */
    private String taskType;
    /**
     * @return The Config template Id of a particular template.
     * 
     */
    private @Nullable String templateId;

    private GetNamespaceScheduledTasksResult() {}
    /**
     * @return Compartment Identifier [OCID] (https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return A user-friendly name that is changeable and that does not have to be unique. Format: a leading alphanumeric, followed by zero or more alphanumerics, underscores, spaces, backslashes, or hyphens in any order). No trailing spaces allowed.
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }
    public List<GetNamespaceScheduledTasksFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    public String namespace() {
        return this.namespace;
    }
    /**
     * @return The list of scheduled_task_collection.
     * 
     */
    public List<GetNamespaceScheduledTasksScheduledTaskCollection> scheduledTaskCollections() {
        return this.scheduledTaskCollections;
    }
    public Optional<String> targetService() {
        return Optional.ofNullable(this.targetService);
    }
    /**
     * @return Task type.
     * 
     */
    public String taskType() {
        return this.taskType;
    }
    /**
     * @return The Config template Id of a particular template.
     * 
     */
    public Optional<String> templateId() {
        return Optional.ofNullable(this.templateId);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetNamespaceScheduledTasksResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String compartmentId;
        private @Nullable String displayName;
        private @Nullable List<GetNamespaceScheduledTasksFilter> filters;
        private String id;
        private String namespace;
        private List<GetNamespaceScheduledTasksScheduledTaskCollection> scheduledTaskCollections;
        private @Nullable String targetService;
        private String taskType;
        private @Nullable String templateId;
        public Builder() {}
        public Builder(GetNamespaceScheduledTasksResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.displayName = defaults.displayName;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.namespace = defaults.namespace;
    	      this.scheduledTaskCollections = defaults.scheduledTaskCollections;
    	      this.targetService = defaults.targetService;
    	      this.taskType = defaults.taskType;
    	      this.templateId = defaults.templateId;
        }

        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            if (compartmentId == null) {
              throw new MissingRequiredPropertyException("GetNamespaceScheduledTasksResult", "compartmentId");
            }
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder displayName(@Nullable String displayName) {

            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetNamespaceScheduledTasksFilter> filters) {

            this.filters = filters;
            return this;
        }
        public Builder filters(GetNamespaceScheduledTasksFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetNamespaceScheduledTasksResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder namespace(String namespace) {
            if (namespace == null) {
              throw new MissingRequiredPropertyException("GetNamespaceScheduledTasksResult", "namespace");
            }
            this.namespace = namespace;
            return this;
        }
        @CustomType.Setter
        public Builder scheduledTaskCollections(List<GetNamespaceScheduledTasksScheduledTaskCollection> scheduledTaskCollections) {
            if (scheduledTaskCollections == null) {
              throw new MissingRequiredPropertyException("GetNamespaceScheduledTasksResult", "scheduledTaskCollections");
            }
            this.scheduledTaskCollections = scheduledTaskCollections;
            return this;
        }
        public Builder scheduledTaskCollections(GetNamespaceScheduledTasksScheduledTaskCollection... scheduledTaskCollections) {
            return scheduledTaskCollections(List.of(scheduledTaskCollections));
        }
        @CustomType.Setter
        public Builder targetService(@Nullable String targetService) {

            this.targetService = targetService;
            return this;
        }
        @CustomType.Setter
        public Builder taskType(String taskType) {
            if (taskType == null) {
              throw new MissingRequiredPropertyException("GetNamespaceScheduledTasksResult", "taskType");
            }
            this.taskType = taskType;
            return this;
        }
        @CustomType.Setter
        public Builder templateId(@Nullable String templateId) {

            this.templateId = templateId;
            return this;
        }
        public GetNamespaceScheduledTasksResult build() {
            final var _resultValue = new GetNamespaceScheduledTasksResult();
            _resultValue.compartmentId = compartmentId;
            _resultValue.displayName = displayName;
            _resultValue.filters = filters;
            _resultValue.id = id;
            _resultValue.namespace = namespace;
            _resultValue.scheduledTaskCollections = scheduledTaskCollections;
            _resultValue.targetService = targetService;
            _resultValue.taskType = taskType;
            _resultValue.templateId = templateId;
            return _resultValue;
        }
    }
}
