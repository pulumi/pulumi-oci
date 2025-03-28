// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.OsManagementHub.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class ManagementStationPeerManagementStationArgs extends com.pulumi.resources.ResourceArgs {

    public static final ManagementStationPeerManagementStationArgs Empty = new ManagementStationPeerManagementStationArgs();

    /**
     * (Updatable) User-friendly name for the management station. Does not have to be unique and you can change the name later. Avoid entering confidential information.
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return (Updatable) User-friendly name for the management station. Does not have to be unique and you can change the name later. Avoid entering confidential information.
     * 
     */
    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the management station.
     * 
     */
    @Import(name="id")
    private @Nullable Output<String> id;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the management station.
     * 
     */
    public Optional<Output<String>> id() {
        return Optional.ofNullable(this.id);
    }

    private ManagementStationPeerManagementStationArgs() {}

    private ManagementStationPeerManagementStationArgs(ManagementStationPeerManagementStationArgs $) {
        this.displayName = $.displayName;
        this.id = $.id;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(ManagementStationPeerManagementStationArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private ManagementStationPeerManagementStationArgs $;

        public Builder() {
            $ = new ManagementStationPeerManagementStationArgs();
        }

        public Builder(ManagementStationPeerManagementStationArgs defaults) {
            $ = new ManagementStationPeerManagementStationArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param displayName (Updatable) User-friendly name for the management station. Does not have to be unique and you can change the name later. Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName (Updatable) User-friendly name for the management station. Does not have to be unique and you can change the name later. Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        /**
         * @param id The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the management station.
         * 
         * @return builder
         * 
         */
        public Builder id(@Nullable Output<String> id) {
            $.id = id;
            return this;
        }

        /**
         * @param id The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the management station.
         * 
         * @return builder
         * 
         */
        public Builder id(String id) {
            return id(Output.of(id));
        }

        public ManagementStationPeerManagementStationArgs build() {
            return $;
        }
    }

}
