// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.OsManagementHub.inputs;

import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;


public final class GetSoftwareSourcePackageGroupPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetSoftwareSourcePackageGroupPlainArgs Empty = new GetSoftwareSourcePackageGroupPlainArgs();

    /**
     * The unique package group identifier.
     * 
     */
    @Import(name="packageGroupId", required=true)
    private String packageGroupId;

    /**
     * @return The unique package group identifier.
     * 
     */
    public String packageGroupId() {
        return this.packageGroupId;
    }

    /**
     * The software source OCID.
     * 
     */
    @Import(name="softwareSourceId", required=true)
    private String softwareSourceId;

    /**
     * @return The software source OCID.
     * 
     */
    public String softwareSourceId() {
        return this.softwareSourceId;
    }

    private GetSoftwareSourcePackageGroupPlainArgs() {}

    private GetSoftwareSourcePackageGroupPlainArgs(GetSoftwareSourcePackageGroupPlainArgs $) {
        this.packageGroupId = $.packageGroupId;
        this.softwareSourceId = $.softwareSourceId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetSoftwareSourcePackageGroupPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetSoftwareSourcePackageGroupPlainArgs $;

        public Builder() {
            $ = new GetSoftwareSourcePackageGroupPlainArgs();
        }

        public Builder(GetSoftwareSourcePackageGroupPlainArgs defaults) {
            $ = new GetSoftwareSourcePackageGroupPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param packageGroupId The unique package group identifier.
         * 
         * @return builder
         * 
         */
        public Builder packageGroupId(String packageGroupId) {
            $.packageGroupId = packageGroupId;
            return this;
        }

        /**
         * @param softwareSourceId The software source OCID.
         * 
         * @return builder
         * 
         */
        public Builder softwareSourceId(String softwareSourceId) {
            $.softwareSourceId = softwareSourceId;
            return this;
        }

        public GetSoftwareSourcePackageGroupPlainArgs build() {
            $.packageGroupId = Objects.requireNonNull($.packageGroupId, "expected parameter 'packageGroupId' to be non-null");
            $.softwareSourceId = Objects.requireNonNull($.softwareSourceId, "expected parameter 'softwareSourceId' to be non-null");
            return $;
        }
    }

}