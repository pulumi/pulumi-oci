// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.OsManagementHub.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class ManagementStationRefreshManagementState extends com.pulumi.resources.ResourceArgs {

    public static final ManagementStationRefreshManagementState Empty = new ManagementStationRefreshManagementState();

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the management station.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Import(name="managementStationId")
    private @Nullable Output<String> managementStationId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the management station.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Optional<Output<String>> managementStationId() {
        return Optional.ofNullable(this.managementStationId);
    }

    private ManagementStationRefreshManagementState() {}

    private ManagementStationRefreshManagementState(ManagementStationRefreshManagementState $) {
        this.managementStationId = $.managementStationId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(ManagementStationRefreshManagementState defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private ManagementStationRefreshManagementState $;

        public Builder() {
            $ = new ManagementStationRefreshManagementState();
        }

        public Builder(ManagementStationRefreshManagementState defaults) {
            $ = new ManagementStationRefreshManagementState(Objects.requireNonNull(defaults));
        }

        /**
         * @param managementStationId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the management station.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder managementStationId(@Nullable Output<String> managementStationId) {
            $.managementStationId = managementStationId;
            return this;
        }

        /**
         * @param managementStationId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the management station.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder managementStationId(String managementStationId) {
            return managementStationId(Output.of(managementStationId));
        }

        public ManagementStationRefreshManagementState build() {
            return $;
        }
    }

}
