// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class KeyStoreTypeDetails {
    /**
     * @return (Updatable) The administrator username to connect to Oracle Key Vault
     * 
     */
    private String adminUsername;
    /**
     * @return (Updatable) The list of Oracle Key Vault connection IP addresses.
     * 
     */
    private List<String> connectionIps;
    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Oracle Cloud Infrastructure [secret](https://docs.cloud.oracle.com/iaas/Content/KeyManagement/Concepts/keyoverview.htm#concepts).
     * 
     */
    private String secretId;
    /**
     * @return (Updatable) The type of key store.
     * 
     */
    private String type;
    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Oracle Cloud Infrastructure [vault](https://docs.cloud.oracle.com/iaas/Content/KeyManagement/Concepts/keyoverview.htm#concepts).
     * 
     */
    private String vaultId;

    private KeyStoreTypeDetails() {}
    /**
     * @return (Updatable) The administrator username to connect to Oracle Key Vault
     * 
     */
    public String adminUsername() {
        return this.adminUsername;
    }
    /**
     * @return (Updatable) The list of Oracle Key Vault connection IP addresses.
     * 
     */
    public List<String> connectionIps() {
        return this.connectionIps;
    }
    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Oracle Cloud Infrastructure [secret](https://docs.cloud.oracle.com/iaas/Content/KeyManagement/Concepts/keyoverview.htm#concepts).
     * 
     */
    public String secretId() {
        return this.secretId;
    }
    /**
     * @return (Updatable) The type of key store.
     * 
     */
    public String type() {
        return this.type;
    }
    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Oracle Cloud Infrastructure [vault](https://docs.cloud.oracle.com/iaas/Content/KeyManagement/Concepts/keyoverview.htm#concepts).
     * 
     */
    public String vaultId() {
        return this.vaultId;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(KeyStoreTypeDetails defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String adminUsername;
        private List<String> connectionIps;
        private String secretId;
        private String type;
        private String vaultId;
        public Builder() {}
        public Builder(KeyStoreTypeDetails defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.adminUsername = defaults.adminUsername;
    	      this.connectionIps = defaults.connectionIps;
    	      this.secretId = defaults.secretId;
    	      this.type = defaults.type;
    	      this.vaultId = defaults.vaultId;
        }

        @CustomType.Setter
        public Builder adminUsername(String adminUsername) {
            this.adminUsername = Objects.requireNonNull(adminUsername);
            return this;
        }
        @CustomType.Setter
        public Builder connectionIps(List<String> connectionIps) {
            this.connectionIps = Objects.requireNonNull(connectionIps);
            return this;
        }
        public Builder connectionIps(String... connectionIps) {
            return connectionIps(List.of(connectionIps));
        }
        @CustomType.Setter
        public Builder secretId(String secretId) {
            this.secretId = Objects.requireNonNull(secretId);
            return this;
        }
        @CustomType.Setter
        public Builder type(String type) {
            this.type = Objects.requireNonNull(type);
            return this;
        }
        @CustomType.Setter
        public Builder vaultId(String vaultId) {
            this.vaultId = Objects.requireNonNull(vaultId);
            return this;
        }
        public KeyStoreTypeDetails build() {
            final var o = new KeyStoreTypeDetails();
            o.adminUsername = adminUsername;
            o.connectionIps = connectionIps;
            o.secretId = secretId;
            o.type = type;
            o.vaultId = vaultId;
            return o;
        }
    }
}