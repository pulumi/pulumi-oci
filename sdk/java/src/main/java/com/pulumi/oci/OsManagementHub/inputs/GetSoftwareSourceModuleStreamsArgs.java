// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.OsManagementHub.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.OsManagementHub.inputs.GetSoftwareSourceModuleStreamsFilterArgs;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetSoftwareSourceModuleStreamsArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetSoftwareSourceModuleStreamsArgs Empty = new GetSoftwareSourceModuleStreamsArgs();

    @Import(name="filters")
    private @Nullable Output<List<GetSoftwareSourceModuleStreamsFilterArgs>> filters;

    public Optional<Output<List<GetSoftwareSourceModuleStreamsFilterArgs>>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * A boolean variable that is used to list only the latest versions of packages, module streams, and stream profiles when set to true. All packages, module streams, and stream profiles are returned when set to false.
     * 
     */
    @Import(name="isLatest")
    private @Nullable Output<Boolean> isLatest;

    /**
     * @return A boolean variable that is used to list only the latest versions of packages, module streams, and stream profiles when set to true. All packages, module streams, and stream profiles are returned when set to false.
     * 
     */
    public Optional<Output<Boolean>> isLatest() {
        return Optional.ofNullable(this.isLatest);
    }

    /**
     * The name of a module. This parameter is required if a streamName is specified.
     * 
     */
    @Import(name="moduleName")
    private @Nullable Output<String> moduleName;

    /**
     * @return The name of a module. This parameter is required if a streamName is specified.
     * 
     */
    public Optional<Output<String>> moduleName() {
        return Optional.ofNullable(this.moduleName);
    }

    /**
     * A filter to return resources that may partially match the module name given.
     * 
     */
    @Import(name="moduleNameContains")
    private @Nullable Output<String> moduleNameContains;

    /**
     * @return A filter to return resources that may partially match the module name given.
     * 
     */
    public Optional<Output<String>> moduleNameContains() {
        return Optional.ofNullable(this.moduleNameContains);
    }

    /**
     * The name of the entity to be queried.
     * 
     */
    @Import(name="name")
    private @Nullable Output<String> name;

    /**
     * @return The name of the entity to be queried.
     * 
     */
    public Optional<Output<String>> name() {
        return Optional.ofNullable(this.name);
    }

    /**
     * The software source OCID.
     * 
     */
    @Import(name="softwareSourceId", required=true)
    private Output<String> softwareSourceId;

    /**
     * @return The software source OCID.
     * 
     */
    public Output<String> softwareSourceId() {
        return this.softwareSourceId;
    }

    private GetSoftwareSourceModuleStreamsArgs() {}

    private GetSoftwareSourceModuleStreamsArgs(GetSoftwareSourceModuleStreamsArgs $) {
        this.filters = $.filters;
        this.isLatest = $.isLatest;
        this.moduleName = $.moduleName;
        this.moduleNameContains = $.moduleNameContains;
        this.name = $.name;
        this.softwareSourceId = $.softwareSourceId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetSoftwareSourceModuleStreamsArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetSoftwareSourceModuleStreamsArgs $;

        public Builder() {
            $ = new GetSoftwareSourceModuleStreamsArgs();
        }

        public Builder(GetSoftwareSourceModuleStreamsArgs defaults) {
            $ = new GetSoftwareSourceModuleStreamsArgs(Objects.requireNonNull(defaults));
        }

        public Builder filters(@Nullable Output<List<GetSoftwareSourceModuleStreamsFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(List<GetSoftwareSourceModuleStreamsFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        public Builder filters(GetSoftwareSourceModuleStreamsFilterArgs... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param isLatest A boolean variable that is used to list only the latest versions of packages, module streams, and stream profiles when set to true. All packages, module streams, and stream profiles are returned when set to false.
         * 
         * @return builder
         * 
         */
        public Builder isLatest(@Nullable Output<Boolean> isLatest) {
            $.isLatest = isLatest;
            return this;
        }

        /**
         * @param isLatest A boolean variable that is used to list only the latest versions of packages, module streams, and stream profiles when set to true. All packages, module streams, and stream profiles are returned when set to false.
         * 
         * @return builder
         * 
         */
        public Builder isLatest(Boolean isLatest) {
            return isLatest(Output.of(isLatest));
        }

        /**
         * @param moduleName The name of a module. This parameter is required if a streamName is specified.
         * 
         * @return builder
         * 
         */
        public Builder moduleName(@Nullable Output<String> moduleName) {
            $.moduleName = moduleName;
            return this;
        }

        /**
         * @param moduleName The name of a module. This parameter is required if a streamName is specified.
         * 
         * @return builder
         * 
         */
        public Builder moduleName(String moduleName) {
            return moduleName(Output.of(moduleName));
        }

        /**
         * @param moduleNameContains A filter to return resources that may partially match the module name given.
         * 
         * @return builder
         * 
         */
        public Builder moduleNameContains(@Nullable Output<String> moduleNameContains) {
            $.moduleNameContains = moduleNameContains;
            return this;
        }

        /**
         * @param moduleNameContains A filter to return resources that may partially match the module name given.
         * 
         * @return builder
         * 
         */
        public Builder moduleNameContains(String moduleNameContains) {
            return moduleNameContains(Output.of(moduleNameContains));
        }

        /**
         * @param name The name of the entity to be queried.
         * 
         * @return builder
         * 
         */
        public Builder name(@Nullable Output<String> name) {
            $.name = name;
            return this;
        }

        /**
         * @param name The name of the entity to be queried.
         * 
         * @return builder
         * 
         */
        public Builder name(String name) {
            return name(Output.of(name));
        }

        /**
         * @param softwareSourceId The software source OCID.
         * 
         * @return builder
         * 
         */
        public Builder softwareSourceId(Output<String> softwareSourceId) {
            $.softwareSourceId = softwareSourceId;
            return this;
        }

        /**
         * @param softwareSourceId The software source OCID.
         * 
         * @return builder
         * 
         */
        public Builder softwareSourceId(String softwareSourceId) {
            return softwareSourceId(Output.of(softwareSourceId));
        }

        public GetSoftwareSourceModuleStreamsArgs build() {
            $.softwareSourceId = Objects.requireNonNull($.softwareSourceId, "expected parameter 'softwareSourceId' to be non-null");
            return $;
        }
    }

}