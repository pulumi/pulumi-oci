// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Logging.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.oci.Logging.inputs.GetUnifiedAgentConfigurationsFilter;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetUnifiedAgentConfigurationsPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetUnifiedAgentConfigurationsPlainArgs Empty = new GetUnifiedAgentConfigurationsPlainArgs();

    /**
     * Compartment OCID to list resources in. See compartmentIdInSubtree for nested compartments traversal.
     * 
     */
    @Import(name="compartmentId", required=true)
    private String compartmentId;

    /**
     * @return Compartment OCID to list resources in. See compartmentIdInSubtree for nested compartments traversal.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }

    /**
     * Resource name
     * 
     */
    @Import(name="displayName")
    private @Nullable String displayName;

    /**
     * @return Resource name
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    @Import(name="filters")
    private @Nullable List<GetUnifiedAgentConfigurationsFilter> filters;

    public Optional<List<GetUnifiedAgentConfigurationsFilter>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * The OCID of a group or a dynamic group.
     * 
     */
    @Import(name="groupId")
    private @Nullable String groupId;

    /**
     * @return The OCID of a group or a dynamic group.
     * 
     */
    public Optional<String> groupId() {
        return Optional.ofNullable(this.groupId);
    }

    /**
     * Specifies whether or not nested compartments should be traversed. Defaults to false.
     * 
     */
    @Import(name="isCompartmentIdInSubtree")
    private @Nullable Boolean isCompartmentIdInSubtree;

    /**
     * @return Specifies whether or not nested compartments should be traversed. Defaults to false.
     * 
     */
    public Optional<Boolean> isCompartmentIdInSubtree() {
        return Optional.ofNullable(this.isCompartmentIdInSubtree);
    }

    /**
     * Custom log OCID to list resources with the log as destination.
     * 
     */
    @Import(name="logId")
    private @Nullable String logId;

    /**
     * @return Custom log OCID to list resources with the log as destination.
     * 
     */
    public Optional<String> logId() {
        return Optional.ofNullable(this.logId);
    }

    /**
     * Lifecycle state of the log object
     * 
     */
    @Import(name="state")
    private @Nullable String state;

    /**
     * @return Lifecycle state of the log object
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }

    private GetUnifiedAgentConfigurationsPlainArgs() {}

    private GetUnifiedAgentConfigurationsPlainArgs(GetUnifiedAgentConfigurationsPlainArgs $) {
        this.compartmentId = $.compartmentId;
        this.displayName = $.displayName;
        this.filters = $.filters;
        this.groupId = $.groupId;
        this.isCompartmentIdInSubtree = $.isCompartmentIdInSubtree;
        this.logId = $.logId;
        this.state = $.state;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetUnifiedAgentConfigurationsPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetUnifiedAgentConfigurationsPlainArgs $;

        public Builder() {
            $ = new GetUnifiedAgentConfigurationsPlainArgs();
        }

        public Builder(GetUnifiedAgentConfigurationsPlainArgs defaults) {
            $ = new GetUnifiedAgentConfigurationsPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId Compartment OCID to list resources in. See compartmentIdInSubtree for nested compartments traversal.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param displayName Resource name
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable String displayName) {
            $.displayName = displayName;
            return this;
        }

        public Builder filters(@Nullable List<GetUnifiedAgentConfigurationsFilter> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(GetUnifiedAgentConfigurationsFilter... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param groupId The OCID of a group or a dynamic group.
         * 
         * @return builder
         * 
         */
        public Builder groupId(@Nullable String groupId) {
            $.groupId = groupId;
            return this;
        }

        /**
         * @param isCompartmentIdInSubtree Specifies whether or not nested compartments should be traversed. Defaults to false.
         * 
         * @return builder
         * 
         */
        public Builder isCompartmentIdInSubtree(@Nullable Boolean isCompartmentIdInSubtree) {
            $.isCompartmentIdInSubtree = isCompartmentIdInSubtree;
            return this;
        }

        /**
         * @param logId Custom log OCID to list resources with the log as destination.
         * 
         * @return builder
         * 
         */
        public Builder logId(@Nullable String logId) {
            $.logId = logId;
            return this;
        }

        /**
         * @param state Lifecycle state of the log object
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable String state) {
            $.state = state;
            return this;
        }

        public GetUnifiedAgentConfigurationsPlainArgs build() {
            $.compartmentId = Objects.requireNonNull($.compartmentId, "expected parameter 'compartmentId' to be non-null");
            return $;
        }
    }

}