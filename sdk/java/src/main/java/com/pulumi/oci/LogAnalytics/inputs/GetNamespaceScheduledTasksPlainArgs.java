// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.LogAnalytics.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.LogAnalytics.inputs.GetNamespaceScheduledTasksFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetNamespaceScheduledTasksPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetNamespaceScheduledTasksPlainArgs Empty = new GetNamespaceScheduledTasksPlainArgs();

    /**
     * The ID of the compartment in which to list resources.
     * 
     */
    @Import(name="compartmentId", required=true)
    private String compartmentId;

    /**
     * @return The ID of the compartment in which to list resources.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }

    /**
     * A filter to return only resources that match the given display name exactly.
     * 
     */
    @Import(name="displayName")
    private @Nullable String displayName;

    /**
     * @return A filter to return only resources that match the given display name exactly.
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    @Import(name="filters")
    private @Nullable List<GetNamespaceScheduledTasksFilter> filters;

    public Optional<List<GetNamespaceScheduledTasksFilter>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * The Logging Analytics namespace used for the request.
     * 
     */
    @Import(name="namespace", required=true)
    private String namespace;

    /**
     * @return The Logging Analytics namespace used for the request.
     * 
     */
    public String namespace() {
        return this.namespace;
    }

    /**
     * The target service to use for filtering.
     * 
     */
    @Import(name="targetService")
    private @Nullable String targetService;

    /**
     * @return The target service to use for filtering.
     * 
     */
    public Optional<String> targetService() {
        return Optional.ofNullable(this.targetService);
    }

    /**
     * Required parameter to specify schedule task type.
     * 
     */
    @Import(name="taskType", required=true)
    private String taskType;

    /**
     * @return Required parameter to specify schedule task type.
     * 
     */
    public String taskType() {
        return this.taskType;
    }

    /**
     * A filter to return only scheduled tasks whose stream action templateId matches the given id  exactly.
     * 
     */
    @Import(name="templateId")
    private @Nullable String templateId;

    /**
     * @return A filter to return only scheduled tasks whose stream action templateId matches the given id  exactly.
     * 
     */
    public Optional<String> templateId() {
        return Optional.ofNullable(this.templateId);
    }

    private GetNamespaceScheduledTasksPlainArgs() {}

    private GetNamespaceScheduledTasksPlainArgs(GetNamespaceScheduledTasksPlainArgs $) {
        this.compartmentId = $.compartmentId;
        this.displayName = $.displayName;
        this.filters = $.filters;
        this.namespace = $.namespace;
        this.targetService = $.targetService;
        this.taskType = $.taskType;
        this.templateId = $.templateId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetNamespaceScheduledTasksPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetNamespaceScheduledTasksPlainArgs $;

        public Builder() {
            $ = new GetNamespaceScheduledTasksPlainArgs();
        }

        public Builder(GetNamespaceScheduledTasksPlainArgs defaults) {
            $ = new GetNamespaceScheduledTasksPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId The ID of the compartment in which to list resources.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param displayName A filter to return only resources that match the given display name exactly.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable String displayName) {
            $.displayName = displayName;
            return this;
        }

        public Builder filters(@Nullable List<GetNamespaceScheduledTasksFilter> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(GetNamespaceScheduledTasksFilter... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param namespace The Logging Analytics namespace used for the request.
         * 
         * @return builder
         * 
         */
        public Builder namespace(String namespace) {
            $.namespace = namespace;
            return this;
        }

        /**
         * @param targetService The target service to use for filtering.
         * 
         * @return builder
         * 
         */
        public Builder targetService(@Nullable String targetService) {
            $.targetService = targetService;
            return this;
        }

        /**
         * @param taskType Required parameter to specify schedule task type.
         * 
         * @return builder
         * 
         */
        public Builder taskType(String taskType) {
            $.taskType = taskType;
            return this;
        }

        /**
         * @param templateId A filter to return only scheduled tasks whose stream action templateId matches the given id  exactly.
         * 
         * @return builder
         * 
         */
        public Builder templateId(@Nullable String templateId) {
            $.templateId = templateId;
            return this;
        }

        public GetNamespaceScheduledTasksPlainArgs build() {
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("GetNamespaceScheduledTasksPlainArgs", "compartmentId");
            }
            if ($.namespace == null) {
                throw new MissingRequiredPropertyException("GetNamespaceScheduledTasksPlainArgs", "namespace");
            }
            if ($.taskType == null) {
                throw new MissingRequiredPropertyException("GetNamespaceScheduledTasksPlainArgs", "taskType");
            }
            return $;
        }
    }

}
