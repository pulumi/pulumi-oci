// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;


public final class CrossConnectGroupMacsecPropertiesPrimaryKeyArgs extends com.pulumi.resources.ResourceArgs {

    public static final CrossConnectGroupMacsecPropertiesPrimaryKeyArgs Empty = new CrossConnectGroupMacsecPropertiesPrimaryKeyArgs();

    /**
     * Secret [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) containing the Connectivity Association Key (CAK) of this MACsec key.
     * 
     */
    @Import(name="connectivityAssociationKeySecretId", required=true)
    private Output<String> connectivityAssociationKeySecretId;

    /**
     * @return Secret [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) containing the Connectivity Association Key (CAK) of this MACsec key.
     * 
     */
    public Output<String> connectivityAssociationKeySecretId() {
        return this.connectivityAssociationKeySecretId;
    }

    /**
     * The secret version of the `connectivityAssociationKey` secret in Vault.
     * 
     */
    @Import(name="connectivityAssociationKeySecretVersion", required=true)
    private Output<String> connectivityAssociationKeySecretVersion;

    /**
     * @return The secret version of the `connectivityAssociationKey` secret in Vault.
     * 
     */
    public Output<String> connectivityAssociationKeySecretVersion() {
        return this.connectivityAssociationKeySecretVersion;
    }

    /**
     * Secret [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) containing the Connectivity association Key Name (CKN) of this MACsec key.
     * 
     */
    @Import(name="connectivityAssociationNameSecretId", required=true)
    private Output<String> connectivityAssociationNameSecretId;

    /**
     * @return Secret [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) containing the Connectivity association Key Name (CKN) of this MACsec key.
     * 
     */
    public Output<String> connectivityAssociationNameSecretId() {
        return this.connectivityAssociationNameSecretId;
    }

    /**
     * The secret version of the connectivity association name secret in Vault.
     * 
     */
    @Import(name="connectivityAssociationNameSecretVersion", required=true)
    private Output<String> connectivityAssociationNameSecretVersion;

    /**
     * @return The secret version of the connectivity association name secret in Vault.
     * 
     */
    public Output<String> connectivityAssociationNameSecretVersion() {
        return this.connectivityAssociationNameSecretVersion;
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
         * @param connectivityAssociationKeySecretId Secret [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) containing the Connectivity Association Key (CAK) of this MACsec key.
         * 
         * @return builder
         * 
         */
        public Builder connectivityAssociationKeySecretId(Output<String> connectivityAssociationKeySecretId) {
            $.connectivityAssociationKeySecretId = connectivityAssociationKeySecretId;
            return this;
        }

        /**
         * @param connectivityAssociationKeySecretId Secret [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) containing the Connectivity Association Key (CAK) of this MACsec key.
         * 
         * @return builder
         * 
         */
        public Builder connectivityAssociationKeySecretId(String connectivityAssociationKeySecretId) {
            return connectivityAssociationKeySecretId(Output.of(connectivityAssociationKeySecretId));
        }

        /**
         * @param connectivityAssociationKeySecretVersion The secret version of the `connectivityAssociationKey` secret in Vault.
         * 
         * @return builder
         * 
         */
        public Builder connectivityAssociationKeySecretVersion(Output<String> connectivityAssociationKeySecretVersion) {
            $.connectivityAssociationKeySecretVersion = connectivityAssociationKeySecretVersion;
            return this;
        }

        /**
         * @param connectivityAssociationKeySecretVersion The secret version of the `connectivityAssociationKey` secret in Vault.
         * 
         * @return builder
         * 
         */
        public Builder connectivityAssociationKeySecretVersion(String connectivityAssociationKeySecretVersion) {
            return connectivityAssociationKeySecretVersion(Output.of(connectivityAssociationKeySecretVersion));
        }

        /**
         * @param connectivityAssociationNameSecretId Secret [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) containing the Connectivity association Key Name (CKN) of this MACsec key.
         * 
         * @return builder
         * 
         */
        public Builder connectivityAssociationNameSecretId(Output<String> connectivityAssociationNameSecretId) {
            $.connectivityAssociationNameSecretId = connectivityAssociationNameSecretId;
            return this;
        }

        /**
         * @param connectivityAssociationNameSecretId Secret [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) containing the Connectivity association Key Name (CKN) of this MACsec key.
         * 
         * @return builder
         * 
         */
        public Builder connectivityAssociationNameSecretId(String connectivityAssociationNameSecretId) {
            return connectivityAssociationNameSecretId(Output.of(connectivityAssociationNameSecretId));
        }

        /**
         * @param connectivityAssociationNameSecretVersion The secret version of the connectivity association name secret in Vault.
         * 
         * @return builder
         * 
         */
        public Builder connectivityAssociationNameSecretVersion(Output<String> connectivityAssociationNameSecretVersion) {
            $.connectivityAssociationNameSecretVersion = connectivityAssociationNameSecretVersion;
            return this;
        }

        /**
         * @param connectivityAssociationNameSecretVersion The secret version of the connectivity association name secret in Vault.
         * 
         * @return builder
         * 
         */
        public Builder connectivityAssociationNameSecretVersion(String connectivityAssociationNameSecretVersion) {
            return connectivityAssociationNameSecretVersion(Output.of(connectivityAssociationNameSecretVersion));
        }

        public CrossConnectGroupMacsecPropertiesPrimaryKeyArgs build() {
            $.connectivityAssociationKeySecretId = Objects.requireNonNull($.connectivityAssociationKeySecretId, "expected parameter 'connectivityAssociationKeySecretId' to be non-null");
            $.connectivityAssociationKeySecretVersion = Objects.requireNonNull($.connectivityAssociationKeySecretVersion, "expected parameter 'connectivityAssociationKeySecretVersion' to be non-null");
            $.connectivityAssociationNameSecretId = Objects.requireNonNull($.connectivityAssociationNameSecretId, "expected parameter 'connectivityAssociationNameSecretId' to be non-null");
            $.connectivityAssociationNameSecretVersion = Objects.requireNonNull($.connectivityAssociationNameSecretVersion, "expected parameter 'connectivityAssociationNameSecretVersion' to be non-null");
            return $;
        }
    }

}
