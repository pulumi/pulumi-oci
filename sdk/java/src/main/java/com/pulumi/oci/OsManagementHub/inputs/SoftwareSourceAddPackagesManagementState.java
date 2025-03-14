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


public final class SoftwareSourceAddPackagesManagementState extends com.pulumi.resources.ResourceArgs {

    public static final SoftwareSourceAddPackagesManagementState Empty = new SoftwareSourceAddPackagesManagementState();

    /**
     * List of packages specified by the full package name (NEVRA.rpm).
     * 
     */
    @Import(name="packages")
    private @Nullable Output<List<String>> packages;

    /**
     * @return List of packages specified by the full package name (NEVRA.rpm).
     * 
     */
    public Optional<Output<List<String>>> packages() {
        return Optional.ofNullable(this.packages);
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the software source.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Import(name="softwareSourceId")
    private @Nullable Output<String> softwareSourceId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the software source.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Optional<Output<String>> softwareSourceId() {
        return Optional.ofNullable(this.softwareSourceId);
    }

    private SoftwareSourceAddPackagesManagementState() {}

    private SoftwareSourceAddPackagesManagementState(SoftwareSourceAddPackagesManagementState $) {
        this.packages = $.packages;
        this.softwareSourceId = $.softwareSourceId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(SoftwareSourceAddPackagesManagementState defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private SoftwareSourceAddPackagesManagementState $;

        public Builder() {
            $ = new SoftwareSourceAddPackagesManagementState();
        }

        public Builder(SoftwareSourceAddPackagesManagementState defaults) {
            $ = new SoftwareSourceAddPackagesManagementState(Objects.requireNonNull(defaults));
        }

        /**
         * @param packages List of packages specified by the full package name (NEVRA.rpm).
         * 
         * @return builder
         * 
         */
        public Builder packages(@Nullable Output<List<String>> packages) {
            $.packages = packages;
            return this;
        }

        /**
         * @param packages List of packages specified by the full package name (NEVRA.rpm).
         * 
         * @return builder
         * 
         */
        public Builder packages(List<String> packages) {
            return packages(Output.of(packages));
        }

        /**
         * @param packages List of packages specified by the full package name (NEVRA.rpm).
         * 
         * @return builder
         * 
         */
        public Builder packages(String... packages) {
            return packages(List.of(packages));
        }

        /**
         * @param softwareSourceId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the software source.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder softwareSourceId(@Nullable Output<String> softwareSourceId) {
            $.softwareSourceId = softwareSourceId;
            return this;
        }

        /**
         * @param softwareSourceId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the software source.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder softwareSourceId(String softwareSourceId) {
            return softwareSourceId(Output.of(softwareSourceId));
        }

        public SoftwareSourceAddPackagesManagementState build() {
            return $;
        }
    }

}
