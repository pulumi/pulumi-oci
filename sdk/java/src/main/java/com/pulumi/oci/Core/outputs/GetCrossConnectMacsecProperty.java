// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Core.outputs.GetCrossConnectMacsecPropertyPrimaryKey;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetCrossConnectMacsecProperty {
    /**
     * @return Type of encryption cipher suite to use for the MACsec connection.
     * 
     */
    private final String encryptionCipher;
    /**
     * @return An object defining the Secrets-in-Vault OCIDs representing the MACsec key.
     * 
     */
    private final List<GetCrossConnectMacsecPropertyPrimaryKey> primaryKeys;
    /**
     * @return The cross-connect&#39;s current state.
     * 
     */
    private final String state;

    @CustomType.Constructor
    private GetCrossConnectMacsecProperty(
        @CustomType.Parameter("encryptionCipher") String encryptionCipher,
        @CustomType.Parameter("primaryKeys") List<GetCrossConnectMacsecPropertyPrimaryKey> primaryKeys,
        @CustomType.Parameter("state") String state) {
        this.encryptionCipher = encryptionCipher;
        this.primaryKeys = primaryKeys;
        this.state = state;
    }

    /**
     * @return Type of encryption cipher suite to use for the MACsec connection.
     * 
     */
    public String encryptionCipher() {
        return this.encryptionCipher;
    }
    /**
     * @return An object defining the Secrets-in-Vault OCIDs representing the MACsec key.
     * 
     */
    public List<GetCrossConnectMacsecPropertyPrimaryKey> primaryKeys() {
        return this.primaryKeys;
    }
    /**
     * @return The cross-connect&#39;s current state.
     * 
     */
    public String state() {
        return this.state;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetCrossConnectMacsecProperty defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String encryptionCipher;
        private List<GetCrossConnectMacsecPropertyPrimaryKey> primaryKeys;
        private String state;

        public Builder() {
    	      // Empty
        }

        public Builder(GetCrossConnectMacsecProperty defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.encryptionCipher = defaults.encryptionCipher;
    	      this.primaryKeys = defaults.primaryKeys;
    	      this.state = defaults.state;
        }

        public Builder encryptionCipher(String encryptionCipher) {
            this.encryptionCipher = Objects.requireNonNull(encryptionCipher);
            return this;
        }
        public Builder primaryKeys(List<GetCrossConnectMacsecPropertyPrimaryKey> primaryKeys) {
            this.primaryKeys = Objects.requireNonNull(primaryKeys);
            return this;
        }
        public Builder primaryKeys(GetCrossConnectMacsecPropertyPrimaryKey... primaryKeys) {
            return primaryKeys(List.of(primaryKeys));
        }
        public Builder state(String state) {
            this.state = Objects.requireNonNull(state);
            return this;
        }        public GetCrossConnectMacsecProperty build() {
            return new GetCrossConnectMacsecProperty(encryptionCipher, primaryKeys, state);
        }
    }
}
