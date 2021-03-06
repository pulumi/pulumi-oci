// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Core.outputs.GetCrossConnectGroupMacsecPropertyPrimaryKey;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetCrossConnectGroupMacsecProperty {
    /**
     * @return Type of encryption cipher suite to use for the MACsec connection.
     * 
     */
    private final String encryptionCipher;
    /**
     * @return An object defining the Secrets-in-Vault OCIDs representing the MACsec key.
     * 
     */
    private final List<GetCrossConnectGroupMacsecPropertyPrimaryKey> primaryKeys;
    /**
     * @return The cross-connect group&#39;s current state.
     * 
     */
    private final String state;

    @CustomType.Constructor
    private GetCrossConnectGroupMacsecProperty(
        @CustomType.Parameter("encryptionCipher") String encryptionCipher,
        @CustomType.Parameter("primaryKeys") List<GetCrossConnectGroupMacsecPropertyPrimaryKey> primaryKeys,
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
    public List<GetCrossConnectGroupMacsecPropertyPrimaryKey> primaryKeys() {
        return this.primaryKeys;
    }
    /**
     * @return The cross-connect group&#39;s current state.
     * 
     */
    public String state() {
        return this.state;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetCrossConnectGroupMacsecProperty defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String encryptionCipher;
        private List<GetCrossConnectGroupMacsecPropertyPrimaryKey> primaryKeys;
        private String state;

        public Builder() {
    	      // Empty
        }

        public Builder(GetCrossConnectGroupMacsecProperty defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.encryptionCipher = defaults.encryptionCipher;
    	      this.primaryKeys = defaults.primaryKeys;
    	      this.state = defaults.state;
        }

        public Builder encryptionCipher(String encryptionCipher) {
            this.encryptionCipher = Objects.requireNonNull(encryptionCipher);
            return this;
        }
        public Builder primaryKeys(List<GetCrossConnectGroupMacsecPropertyPrimaryKey> primaryKeys) {
            this.primaryKeys = Objects.requireNonNull(primaryKeys);
            return this;
        }
        public Builder primaryKeys(GetCrossConnectGroupMacsecPropertyPrimaryKey... primaryKeys) {
            return primaryKeys(List.of(primaryKeys));
        }
        public Builder state(String state) {
            this.state = Objects.requireNonNull(state);
            return this;
        }        public GetCrossConnectGroupMacsecProperty build() {
            return new GetCrossConnectGroupMacsecProperty(encryptionCipher, primaryKeys, state);
        }
    }
}
