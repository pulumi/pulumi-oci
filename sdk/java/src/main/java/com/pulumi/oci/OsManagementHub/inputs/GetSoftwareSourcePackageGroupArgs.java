// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.OsManagementHub.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;


public final class GetSoftwareSourcePackageGroupArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetSoftwareSourcePackageGroupArgs Empty = new GetSoftwareSourcePackageGroupArgs();

    /**
     * The unique package group identifier.
     * 
     */
    @Import(name="packageGroupId", required=true)
    private Output<String> packageGroupId;

    /**
     * @return The unique package group identifier.
     * 
     */
    public Output<String> packageGroupId() {
        return this.packageGroupId;
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

    private GetSoftwareSourcePackageGroupArgs() {}

    private GetSoftwareSourcePackageGroupArgs(GetSoftwareSourcePackageGroupArgs $) {
        this.packageGroupId = $.packageGroupId;
        this.softwareSourceId = $.softwareSourceId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetSoftwareSourcePackageGroupArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetSoftwareSourcePackageGroupArgs $;

        public Builder() {
            $ = new GetSoftwareSourcePackageGroupArgs();
        }

        public Builder(GetSoftwareSourcePackageGroupArgs defaults) {
            $ = new GetSoftwareSourcePackageGroupArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param packageGroupId The unique package group identifier.
         * 
         * @return builder
         * 
         */
        public Builder packageGroupId(Output<String> packageGroupId) {
            $.packageGroupId = packageGroupId;
            return this;
        }

        /**
         * @param packageGroupId The unique package group identifier.
         * 
         * @return builder
         * 
         */
        public Builder packageGroupId(String packageGroupId) {
            return packageGroupId(Output.of(packageGroupId));
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

        public GetSoftwareSourcePackageGroupArgs build() {
            $.packageGroupId = Objects.requireNonNull($.packageGroupId, "expected parameter 'packageGroupId' to be non-null");
            $.softwareSourceId = Objects.requireNonNull($.softwareSourceId, "expected parameter 'softwareSourceId' to be non-null");
            return $;
        }
    }

}