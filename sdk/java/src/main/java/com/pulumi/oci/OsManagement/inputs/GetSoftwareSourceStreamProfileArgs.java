// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.OsManagement.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.OsManagement.inputs.GetSoftwareSourceStreamProfileFilterArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetSoftwareSourceStreamProfileArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetSoftwareSourceStreamProfileArgs Empty = new GetSoftwareSourceStreamProfileArgs();

    /**
     * The ID of the compartment in which to list resources. This parameter is optional and in some cases may have no effect.
     * 
     */
    @Import(name="compartmentId")
    private @Nullable Output<String> compartmentId;

    /**
     * @return The ID of the compartment in which to list resources. This parameter is optional and in some cases may have no effect.
     * 
     */
    public Optional<Output<String>> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
    }

    @Import(name="filters")
    private @Nullable Output<List<GetSoftwareSourceStreamProfileFilterArgs>> filters;

    public Optional<Output<List<GetSoftwareSourceStreamProfileFilterArgs>>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * The name of a module.  This parameter is required if a streamName is specified.
     * 
     */
    @Import(name="moduleName")
    private @Nullable Output<String> moduleName;

    /**
     * @return The name of a module.  This parameter is required if a streamName is specified.
     * 
     */
    public Optional<Output<String>> moduleName() {
        return Optional.ofNullable(this.moduleName);
    }

    /**
     * The name of the profile of the containing module stream
     * 
     */
    @Import(name="profileName")
    private @Nullable Output<String> profileName;

    /**
     * @return The name of the profile of the containing module stream
     * 
     */
    public Optional<Output<String>> profileName() {
        return Optional.ofNullable(this.profileName);
    }

    /**
     * The OCID of the software source.
     * 
     */
    @Import(name="softwareSourceId", required=true)
    private Output<String> softwareSourceId;

    /**
     * @return The OCID of the software source.
     * 
     */
    public Output<String> softwareSourceId() {
        return this.softwareSourceId;
    }

    /**
     * The name of the stream of the containing module.  This parameter is required if a profileName is specified.
     * 
     */
    @Import(name="streamName")
    private @Nullable Output<String> streamName;

    /**
     * @return The name of the stream of the containing module.  This parameter is required if a profileName is specified.
     * 
     */
    public Optional<Output<String>> streamName() {
        return Optional.ofNullable(this.streamName);
    }

    private GetSoftwareSourceStreamProfileArgs() {}

    private GetSoftwareSourceStreamProfileArgs(GetSoftwareSourceStreamProfileArgs $) {
        this.compartmentId = $.compartmentId;
        this.filters = $.filters;
        this.moduleName = $.moduleName;
        this.profileName = $.profileName;
        this.softwareSourceId = $.softwareSourceId;
        this.streamName = $.streamName;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetSoftwareSourceStreamProfileArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetSoftwareSourceStreamProfileArgs $;

        public Builder() {
            $ = new GetSoftwareSourceStreamProfileArgs();
        }

        public Builder(GetSoftwareSourceStreamProfileArgs defaults) {
            $ = new GetSoftwareSourceStreamProfileArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId The ID of the compartment in which to list resources. This parameter is optional and in some cases may have no effect.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(@Nullable Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId The ID of the compartment in which to list resources. This parameter is optional and in some cases may have no effect.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        public Builder filters(@Nullable Output<List<GetSoftwareSourceStreamProfileFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(List<GetSoftwareSourceStreamProfileFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        public Builder filters(GetSoftwareSourceStreamProfileFilterArgs... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param moduleName The name of a module.  This parameter is required if a streamName is specified.
         * 
         * @return builder
         * 
         */
        public Builder moduleName(@Nullable Output<String> moduleName) {
            $.moduleName = moduleName;
            return this;
        }

        /**
         * @param moduleName The name of a module.  This parameter is required if a streamName is specified.
         * 
         * @return builder
         * 
         */
        public Builder moduleName(String moduleName) {
            return moduleName(Output.of(moduleName));
        }

        /**
         * @param profileName The name of the profile of the containing module stream
         * 
         * @return builder
         * 
         */
        public Builder profileName(@Nullable Output<String> profileName) {
            $.profileName = profileName;
            return this;
        }

        /**
         * @param profileName The name of the profile of the containing module stream
         * 
         * @return builder
         * 
         */
        public Builder profileName(String profileName) {
            return profileName(Output.of(profileName));
        }

        /**
         * @param softwareSourceId The OCID of the software source.
         * 
         * @return builder
         * 
         */
        public Builder softwareSourceId(Output<String> softwareSourceId) {
            $.softwareSourceId = softwareSourceId;
            return this;
        }

        /**
         * @param softwareSourceId The OCID of the software source.
         * 
         * @return builder
         * 
         */
        public Builder softwareSourceId(String softwareSourceId) {
            return softwareSourceId(Output.of(softwareSourceId));
        }

        /**
         * @param streamName The name of the stream of the containing module.  This parameter is required if a profileName is specified.
         * 
         * @return builder
         * 
         */
        public Builder streamName(@Nullable Output<String> streamName) {
            $.streamName = streamName;
            return this;
        }

        /**
         * @param streamName The name of the stream of the containing module.  This parameter is required if a profileName is specified.
         * 
         * @return builder
         * 
         */
        public Builder streamName(String streamName) {
            return streamName(Output.of(streamName));
        }

        public GetSoftwareSourceStreamProfileArgs build() {
            $.softwareSourceId = Objects.requireNonNull($.softwareSourceId, "expected parameter 'softwareSourceId' to be non-null");
            return $;
        }
    }

}