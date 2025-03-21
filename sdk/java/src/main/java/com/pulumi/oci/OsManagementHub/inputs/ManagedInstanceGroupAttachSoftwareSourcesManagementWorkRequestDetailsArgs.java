// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.OsManagementHub.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class ManagedInstanceGroupAttachSoftwareSourcesManagementWorkRequestDetailsArgs extends com.pulumi.resources.ResourceArgs {

    public static final ManagedInstanceGroupAttachSoftwareSourcesManagementWorkRequestDetailsArgs Empty = new ManagedInstanceGroupAttachSoftwareSourcesManagementWorkRequestDetailsArgs();

    /**
     * User-specified information about the job. Avoid entering confidential information.
     * 
     */
    @Import(name="description")
    private @Nullable Output<String> description;

    /**
     * @return User-specified information about the job. Avoid entering confidential information.
     * 
     */
    public Optional<Output<String>> description() {
        return Optional.ofNullable(this.description);
    }

    /**
     * A user-friendly name for the job. The name does not have to be unique. Avoid entering confidential information.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return A user-friendly name for the job. The name does not have to be unique. Avoid entering confidential information.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    private ManagedInstanceGroupAttachSoftwareSourcesManagementWorkRequestDetailsArgs() {}

    private ManagedInstanceGroupAttachSoftwareSourcesManagementWorkRequestDetailsArgs(ManagedInstanceGroupAttachSoftwareSourcesManagementWorkRequestDetailsArgs $) {
        this.description = $.description;
        this.displayName = $.displayName;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(ManagedInstanceGroupAttachSoftwareSourcesManagementWorkRequestDetailsArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private ManagedInstanceGroupAttachSoftwareSourcesManagementWorkRequestDetailsArgs $;

        public Builder() {
            $ = new ManagedInstanceGroupAttachSoftwareSourcesManagementWorkRequestDetailsArgs();
        }

        public Builder(ManagedInstanceGroupAttachSoftwareSourcesManagementWorkRequestDetailsArgs defaults) {
            $ = new ManagedInstanceGroupAttachSoftwareSourcesManagementWorkRequestDetailsArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param description User-specified information about the job. Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder description(@Nullable Output<String> description) {
            $.description = description;
            return this;
        }

        /**
         * @param description User-specified information about the job. Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder description(String description) {
            return description(Output.of(description));
        }

        /**
         * @param displayName A user-friendly name for the job. The name does not have to be unique. Avoid entering confidential information.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName A user-friendly name for the job. The name does not have to be unique. Avoid entering confidential information.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        public ManagedInstanceGroupAttachSoftwareSourcesManagementWorkRequestDetailsArgs build() {
            return $;
        }
    }

}
