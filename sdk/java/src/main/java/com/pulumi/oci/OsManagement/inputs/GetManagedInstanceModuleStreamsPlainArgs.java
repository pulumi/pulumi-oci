// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.OsManagement.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.oci.OsManagement.inputs.GetManagedInstanceModuleStreamsFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetManagedInstanceModuleStreamsPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetManagedInstanceModuleStreamsPlainArgs Empty = new GetManagedInstanceModuleStreamsPlainArgs();

    /**
     * The ID of the compartment in which to list resources. This parameter is optional and in some cases may have no effect.
     * 
     */
    @Import(name="compartmentId")
    private @Nullable String compartmentId;

    /**
     * @return The ID of the compartment in which to list resources. This parameter is optional and in some cases may have no effect.
     * 
     */
    public Optional<String> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
    }

    @Import(name="filters")
    private @Nullable List<GetManagedInstanceModuleStreamsFilter> filters;

    public Optional<List<GetManagedInstanceModuleStreamsFilter>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * OCID for the managed instance
     * 
     */
    @Import(name="managedInstanceId", required=true)
    private String managedInstanceId;

    /**
     * @return OCID for the managed instance
     * 
     */
    public String managedInstanceId() {
        return this.managedInstanceId;
    }

    /**
     * The name of a module.  This parameter is required if a streamName is specified.
     * 
     */
    @Import(name="moduleName")
    private @Nullable String moduleName;

    /**
     * @return The name of a module.  This parameter is required if a streamName is specified.
     * 
     */
    public Optional<String> moduleName() {
        return Optional.ofNullable(this.moduleName);
    }

    /**
     * The name of the stream of the containing module.  This parameter is required if a profileName is specified.
     * 
     */
    @Import(name="streamName")
    private @Nullable String streamName;

    /**
     * @return The name of the stream of the containing module.  This parameter is required if a profileName is specified.
     * 
     */
    public Optional<String> streamName() {
        return Optional.ofNullable(this.streamName);
    }

    /**
     * The status of the stream
     * 
     */
    @Import(name="streamStatus")
    private @Nullable String streamStatus;

    /**
     * @return The status of the stream
     * 
     */
    public Optional<String> streamStatus() {
        return Optional.ofNullable(this.streamStatus);
    }

    private GetManagedInstanceModuleStreamsPlainArgs() {}

    private GetManagedInstanceModuleStreamsPlainArgs(GetManagedInstanceModuleStreamsPlainArgs $) {
        this.compartmentId = $.compartmentId;
        this.filters = $.filters;
        this.managedInstanceId = $.managedInstanceId;
        this.moduleName = $.moduleName;
        this.streamName = $.streamName;
        this.streamStatus = $.streamStatus;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetManagedInstanceModuleStreamsPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetManagedInstanceModuleStreamsPlainArgs $;

        public Builder() {
            $ = new GetManagedInstanceModuleStreamsPlainArgs();
        }

        public Builder(GetManagedInstanceModuleStreamsPlainArgs defaults) {
            $ = new GetManagedInstanceModuleStreamsPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId The ID of the compartment in which to list resources. This parameter is optional and in some cases may have no effect.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(@Nullable String compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        public Builder filters(@Nullable List<GetManagedInstanceModuleStreamsFilter> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(GetManagedInstanceModuleStreamsFilter... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param managedInstanceId OCID for the managed instance
         * 
         * @return builder
         * 
         */
        public Builder managedInstanceId(String managedInstanceId) {
            $.managedInstanceId = managedInstanceId;
            return this;
        }

        /**
         * @param moduleName The name of a module.  This parameter is required if a streamName is specified.
         * 
         * @return builder
         * 
         */
        public Builder moduleName(@Nullable String moduleName) {
            $.moduleName = moduleName;
            return this;
        }

        /**
         * @param streamName The name of the stream of the containing module.  This parameter is required if a profileName is specified.
         * 
         * @return builder
         * 
         */
        public Builder streamName(@Nullable String streamName) {
            $.streamName = streamName;
            return this;
        }

        /**
         * @param streamStatus The status of the stream
         * 
         * @return builder
         * 
         */
        public Builder streamStatus(@Nullable String streamStatus) {
            $.streamStatus = streamStatus;
            return this;
        }

        public GetManagedInstanceModuleStreamsPlainArgs build() {
            $.managedInstanceId = Objects.requireNonNull($.managedInstanceId, "expected parameter 'managedInstanceId' to be non-null");
            return $;
        }
    }

}