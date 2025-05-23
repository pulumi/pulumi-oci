// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class CrossConnectGroupMacsecPropertiesPrimaryKeyArgs extends com.pulumi.resources.ResourceArgs {

    public static final CrossConnectGroupMacsecPropertiesPrimaryKeyArgs Empty = new CrossConnectGroupMacsecPropertiesPrimaryKeyArgs();

    /**
     * (Updatable) Secret [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) containing the Connectivity Association Key (CAK) of this MACsec key.
     * 
     */
    @Import(name="connectivityAssociationKeySecretId", required=true)
    private Output<String> connectivityAssociationKeySecretId;

    /**
     * @return (Updatable) Secret [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) containing the Connectivity Association Key (CAK) of this MACsec key.
     * 
     */
    public Output<String> connectivityAssociationKeySecretId() {
        return this.connectivityAssociationKeySecretId;
    }

    /**
     * (Updatable) The secret version of the `connectivity_association_key_secret_id` secret in Vault.
     * 
     * NOTE: Only the latest secret version will be used.
     * 
     */
    @Import(name="connectivityAssociationKeySecretVersion")
    private @Nullable Output<String> connectivityAssociationKeySecretVersion;

    /**
     * @return (Updatable) The secret version of the `connectivity_association_key_secret_id` secret in Vault.
     * 
     * NOTE: Only the latest secret version will be used.
     * 
     */
    public Optional<Output<String>> connectivityAssociationKeySecretVersion() {
        return Optional.ofNullable(this.connectivityAssociationKeySecretVersion);
    }

    /**
     * (Updatable) Secret [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) containing the Connectivity association Key Name (CKN) of this MACsec key.
     * 
     */
    @Import(name="connectivityAssociationNameSecretId", required=true)
    private Output<String> connectivityAssociationNameSecretId;

    /**
     * @return (Updatable) Secret [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) containing the Connectivity association Key Name (CKN) of this MACsec key.
     * 
     */
    public Output<String> connectivityAssociationNameSecretId() {
        return this.connectivityAssociationNameSecretId;
    }

    /**
     * (Updatable) The secret version of the `connectivity_association_name_secret_id` secret in Vault.
     * 
     * NOTE: Only the latest secret version will be used.
     * 
     */
    @Import(name="connectivityAssociationNameSecretVersion")
    private @Nullable Output<String> connectivityAssociationNameSecretVersion;

    /**
     * @return (Updatable) The secret version of the `connectivity_association_name_secret_id` secret in Vault.
     * 
     * NOTE: Only the latest secret version will be used.
     * 
     */
    public Optional<Output<String>> connectivityAssociationNameSecretVersion() {
        return Optional.ofNullable(this.connectivityAssociationNameSecretVersion);
    }

    private CrossConnectGroupMacsecPropertiesPrimaryKeyArgs() {}

    private CrossConnectGroupMacsecPropertiesPrimaryKeyArgs(CrossConnectGroupMacsecPropertiesPrimaryKeyArgs $) {
        this.connectivityAssociationKeySecretId = $.connectivityAssociationKeySecretId;
        this.connectivityAssociationKeySecretVersion = $.connectivityAssociationKeySecretVersion;
        this.connectivityAssociationNameSecretId = $.connectivityAssociationNameSecretId;
        this.connectivityAssociationNameSecretVersion = $.connectivityAssociationNameSecretVersion;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(CrossConnectGroupMacsecPropertiesPrimaryKeyArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private CrossConnectGroupMacsecPropertiesPrimaryKeyArgs $;

        public Builder() {
            $ = new CrossConnectGroupMacsecPropertiesPrimaryKeyArgs();
        }

        public Builder(CrossConnectGroupMacsecPropertiesPrimaryKeyArgs defaults) {
            $ = new CrossConnectGroupMacsecPropertiesPrimaryKeyArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param connectivityAssociationKeySecretId (Updatable) Secret [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) containing the Connectivity Association Key (CAK) of this MACsec key.
         * 
         * @return builder
         * 
         */
        public Builder connectivityAssociationKeySecretId(Output<String> connectivityAssociationKeySecretId) {
            $.connectivityAssociationKeySecretId = connectivityAssociationKeySecretId;
            return this;
        }

        /**
         * @param connectivityAssociationKeySecretId (Updatable) Secret [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) containing the Connectivity Association Key (CAK) of this MACsec key.
         * 
         * @return builder
         * 
         */
        public Builder connectivityAssociationKeySecretId(String connectivityAssociationKeySecretId) {
            return connectivityAssociationKeySecretId(Output.of(connectivityAssociationKeySecretId));
        }

        /**
         * @param connectivityAssociationKeySecretVersion (Updatable) The secret version of the `connectivity_association_key_secret_id` secret in Vault.
         * 
         * NOTE: Only the latest secret version will be used.
         * 
         * @return builder
         * 
         */
        public Builder connectivityAssociationKeySecretVersion(@Nullable Output<String> connectivityAssociationKeySecretVersion) {
            $.connectivityAssociationKeySecretVersion = connectivityAssociationKeySecretVersion;
            return this;
        }

        /**
         * @param connectivityAssociationKeySecretVersion (Updatable) The secret version of the `connectivity_association_key_secret_id` secret in Vault.
         * 
         * NOTE: Only the latest secret version will be used.
         * 
         * @return builder
         * 
         */
        public Builder connectivityAssociationKeySecretVersion(String connectivityAssociationKeySecretVersion) {
            return connectivityAssociationKeySecretVersion(Output.of(connectivityAssociationKeySecretVersion));
        }

        /**
         * @param connectivityAssociationNameSecretId (Updatable) Secret [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) containing the Connectivity association Key Name (CKN) of this MACsec key.
         * 
         * @return builder
         * 
         */
        public Builder connectivityAssociationNameSecretId(Output<String> connectivityAssociationNameSecretId) {
            $.connectivityAssociationNameSecretId = connectivityAssociationNameSecretId;
            return this;
        }

        /**
         * @param connectivityAssociationNameSecretId (Updatable) Secret [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) containing the Connectivity association Key Name (CKN) of this MACsec key.
         * 
         * @return builder
         * 
         */
        public Builder connectivityAssociationNameSecretId(String connectivityAssociationNameSecretId) {
            return connectivityAssociationNameSecretId(Output.of(connectivityAssociationNameSecretId));
        }

        /**
         * @param connectivityAssociationNameSecretVersion (Updatable) The secret version of the `connectivity_association_name_secret_id` secret in Vault.
         * 
         * NOTE: Only the latest secret version will be used.
         * 
         * @return builder
         * 
         */
        public Builder connectivityAssociationNameSecretVersion(@Nullable Output<String> connectivityAssociationNameSecretVersion) {
            $.connectivityAssociationNameSecretVersion = connectivityAssociationNameSecretVersion;
            return this;
        }

        /**
         * @param connectivityAssociationNameSecretVersion (Updatable) The secret version of the `connectivity_association_name_secret_id` secret in Vault.
         * 
         * NOTE: Only the latest secret version will be used.
         * 
         * @return builder
         * 
         */
        public Builder connectivityAssociationNameSecretVersion(String connectivityAssociationNameSecretVersion) {
            return connectivityAssociationNameSecretVersion(Output.of(connectivityAssociationNameSecretVersion));
        }

        public CrossConnectGroupMacsecPropertiesPrimaryKeyArgs build() {
            if ($.connectivityAssociationKeySecretId == null) {
                throw new MissingRequiredPropertyException("CrossConnectGroupMacsecPropertiesPrimaryKeyArgs", "connectivityAssociationKeySecretId");
            }
            if ($.connectivityAssociationNameSecretId == null) {
                throw new MissingRequiredPropertyException("CrossConnectGroupMacsecPropertiesPrimaryKeyArgs", "connectivityAssociationNameSecretId");
            }
            return $;
        }
    }

}
