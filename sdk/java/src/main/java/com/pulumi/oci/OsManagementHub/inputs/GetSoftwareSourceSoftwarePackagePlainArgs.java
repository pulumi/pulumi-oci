// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.OsManagementHub.inputs;

import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;


public final class GetSoftwareSourceSoftwarePackagePlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetSoftwareSourceSoftwarePackagePlainArgs Empty = new GetSoftwareSourceSoftwarePackagePlainArgs();

    /**
     * The name of the software package.
     * 
     */
    @Import(name="softwarePackageName", required=true)
    private String softwarePackageName;

    /**
     * @return The name of the software package.
     * 
     */
    public String softwarePackageName() {
        return this.softwarePackageName;
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

    private GetSoftwareSourceSoftwarePackagePlainArgs() {}

    private GetSoftwareSourceSoftwarePackagePlainArgs(GetSoftwareSourceSoftwarePackagePlainArgs $) {
        this.softwarePackageName = $.softwarePackageName;
        this.softwareSourceId = $.softwareSourceId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetSoftwareSourceSoftwarePackagePlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetSoftwareSourceSoftwarePackagePlainArgs $;

        public Builder() {
            $ = new GetSoftwareSourceSoftwarePackagePlainArgs();
        }

        public Builder(GetSoftwareSourceSoftwarePackagePlainArgs defaults) {
            $ = new GetSoftwareSourceSoftwarePackagePlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param softwarePackageName The name of the software package.
         * 
         * @return builder
         * 
         */
        public Builder softwarePackageName(String softwarePackageName) {
            $.softwarePackageName = softwarePackageName;
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

        public GetSoftwareSourceSoftwarePackagePlainArgs build() {
            $.softwarePackageName = Objects.requireNonNull($.softwarePackageName, "expected parameter 'softwarePackageName' to be non-null");
            $.softwareSourceId = Objects.requireNonNull($.softwareSourceId, "expected parameter 'softwareSourceId' to be non-null");
            return $;
        }
    }

}