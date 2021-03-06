// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseMigration.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;


public final class ConnectionVaultDetailsArgs extends com.pulumi.resources.ResourceArgs {

    public static final ConnectionVaultDetailsArgs Empty = new ConnectionVaultDetailsArgs();

    /**
     * (Updatable) OCID of the compartment where the secret containing the credentials will be created.
     * 
     */
    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    /**
     * @return (Updatable) OCID of the compartment where the secret containing the credentials will be created.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }

    /**
     * (Updatable) OCID of the vault encryption key
     * 
     */
    @Import(name="keyId", required=true)
    private Output<String> keyId;

    /**
     * @return (Updatable) OCID of the vault encryption key
     * 
     */
    public Output<String> keyId() {
        return this.keyId;
    }

    /**
     * (Updatable) OCID of the vault
     * 
     */
    @Import(name="vaultId", required=true)
    private Output<String> vaultId;

    /**
     * @return (Updatable) OCID of the vault
     * 
     */
    public Output<String> vaultId() {
        return this.vaultId;
    }

    private ConnectionVaultDetailsArgs() {}

    private ConnectionVaultDetailsArgs(ConnectionVaultDetailsArgs $) {
        this.compartmentId = $.compartmentId;
        this.keyId = $.keyId;
        this.vaultId = $.vaultId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(ConnectionVaultDetailsArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private ConnectionVaultDetailsArgs $;

        public Builder() {
            $ = new ConnectionVaultDetailsArgs();
        }

        public Builder(ConnectionVaultDetailsArgs defaults) {
            $ = new ConnectionVaultDetailsArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId (Updatable) OCID of the compartment where the secret containing the credentials will be created.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId (Updatable) OCID of the compartment where the secret containing the credentials will be created.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param keyId (Updatable) OCID of the vault encryption key
         * 
         * @return builder
         * 
         */
        public Builder keyId(Output<String> keyId) {
            $.keyId = keyId;
            return this;
        }

        /**
         * @param keyId (Updatable) OCID of the vault encryption key
         * 
         * @return builder
         * 
         */
        public Builder keyId(String keyId) {
            return keyId(Output.of(keyId));
        }

        /**
         * @param vaultId (Updatable) OCID of the vault
         * 
         * @return builder
         * 
         */
        public Builder vaultId(Output<String> vaultId) {
            $.vaultId = vaultId;
            return this;
        }

        /**
         * @param vaultId (Updatable) OCID of the vault
         * 
         * @return builder
         * 
         */
        public Builder vaultId(String vaultId) {
            return vaultId(Output.of(vaultId));
        }

        public ConnectionVaultDetailsArgs build() {
            $.compartmentId = Objects.requireNonNull($.compartmentId, "expected parameter 'compartmentId' to be non-null");
            $.keyId = Objects.requireNonNull($.keyId, "expected parameter 'keyId' to be non-null");
            $.vaultId = Objects.requireNonNull($.vaultId, "expected parameter 'vaultId' to be non-null");
            return $;
        }
    }

}
