// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.OsManagementHub.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class ProfileAttachSoftwareSourcesManagementState extends com.pulumi.resources.ResourceArgs {

    public static final ProfileAttachSoftwareSourcesManagementState Empty = new ProfileAttachSoftwareSourcesManagementState();

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the registration profile.
     * 
     */
    @Import(name="profileId")
    private @Nullable Output<String> profileId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the registration profile.
     * 
     */
    public Optional<Output<String>> profileId() {
        return Optional.ofNullable(this.profileId);
    }

    /**
     * List of software source [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) to attach to the profile.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Import(name="softwareSources")
    private @Nullable Output<List<String>> softwareSources;

    /**
     * @return List of software source [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) to attach to the profile.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Optional<Output<List<String>>> softwareSources() {
        return Optional.ofNullable(this.softwareSources);
    }

    private ProfileAttachSoftwareSourcesManagementState() {}

    private ProfileAttachSoftwareSourcesManagementState(ProfileAttachSoftwareSourcesManagementState $) {
        this.profileId = $.profileId;
        this.softwareSources = $.softwareSources;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(ProfileAttachSoftwareSourcesManagementState defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private ProfileAttachSoftwareSourcesManagementState $;

        public Builder() {
            $ = new ProfileAttachSoftwareSourcesManagementState();
        }

        public Builder(ProfileAttachSoftwareSourcesManagementState defaults) {
            $ = new ProfileAttachSoftwareSourcesManagementState(Objects.requireNonNull(defaults));
        }

        /**
         * @param profileId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the registration profile.
         * 
         * @return builder
         * 
         */
        public Builder profileId(@Nullable Output<String> profileId) {
            $.profileId = profileId;
            return this;
        }

        /**
         * @param profileId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the registration profile.
         * 
         * @return builder
         * 
         */
        public Builder profileId(String profileId) {
            return profileId(Output.of(profileId));
        }

        /**
         * @param softwareSources List of software source [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) to attach to the profile.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder softwareSources(@Nullable Output<List<String>> softwareSources) {
            $.softwareSources = softwareSources;
            return this;
        }

        /**
         * @param softwareSources List of software source [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) to attach to the profile.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder softwareSources(List<String> softwareSources) {
            return softwareSources(Output.of(softwareSources));
        }

        /**
         * @param softwareSources List of software source [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) to attach to the profile.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder softwareSources(String... softwareSources) {
            return softwareSources(List.of(softwareSources));
        }

        public ProfileAttachSoftwareSourcesManagementState build() {
            return $;
        }
    }

}
