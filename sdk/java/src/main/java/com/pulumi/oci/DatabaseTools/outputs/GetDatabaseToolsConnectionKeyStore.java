// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseTools.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DatabaseTools.outputs.GetDatabaseToolsConnectionKeyStoreKeyStoreContent;
import com.pulumi.oci.DatabaseTools.outputs.GetDatabaseToolsConnectionKeyStoreKeyStorePassword;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetDatabaseToolsConnectionKeyStore {
    /**
     * @return The key store content.
     * 
     */
    private final List<GetDatabaseToolsConnectionKeyStoreKeyStoreContent> keyStoreContents;
    /**
     * @return The key store password.
     * 
     */
    private final List<GetDatabaseToolsConnectionKeyStoreKeyStorePassword> keyStorePasswords;
    /**
     * @return The key store type.
     * 
     */
    private final String keyStoreType;

    @CustomType.Constructor
    private GetDatabaseToolsConnectionKeyStore(
        @CustomType.Parameter("keyStoreContents") List<GetDatabaseToolsConnectionKeyStoreKeyStoreContent> keyStoreContents,
        @CustomType.Parameter("keyStorePasswords") List<GetDatabaseToolsConnectionKeyStoreKeyStorePassword> keyStorePasswords,
        @CustomType.Parameter("keyStoreType") String keyStoreType) {
        this.keyStoreContents = keyStoreContents;
        this.keyStorePasswords = keyStorePasswords;
        this.keyStoreType = keyStoreType;
    }

    /**
     * @return The key store content.
     * 
     */
    public List<GetDatabaseToolsConnectionKeyStoreKeyStoreContent> keyStoreContents() {
        return this.keyStoreContents;
    }
    /**
     * @return The key store password.
     * 
     */
    public List<GetDatabaseToolsConnectionKeyStoreKeyStorePassword> keyStorePasswords() {
        return this.keyStorePasswords;
    }
    /**
     * @return The key store type.
     * 
     */
    public String keyStoreType() {
        return this.keyStoreType;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDatabaseToolsConnectionKeyStore defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private List<GetDatabaseToolsConnectionKeyStoreKeyStoreContent> keyStoreContents;
        private List<GetDatabaseToolsConnectionKeyStoreKeyStorePassword> keyStorePasswords;
        private String keyStoreType;

        public Builder() {
    	      // Empty
        }

        public Builder(GetDatabaseToolsConnectionKeyStore defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.keyStoreContents = defaults.keyStoreContents;
    	      this.keyStorePasswords = defaults.keyStorePasswords;
    	      this.keyStoreType = defaults.keyStoreType;
        }

        public Builder keyStoreContents(List<GetDatabaseToolsConnectionKeyStoreKeyStoreContent> keyStoreContents) {
            this.keyStoreContents = Objects.requireNonNull(keyStoreContents);
            return this;
        }
        public Builder keyStoreContents(GetDatabaseToolsConnectionKeyStoreKeyStoreContent... keyStoreContents) {
            return keyStoreContents(List.of(keyStoreContents));
        }
        public Builder keyStorePasswords(List<GetDatabaseToolsConnectionKeyStoreKeyStorePassword> keyStorePasswords) {
            this.keyStorePasswords = Objects.requireNonNull(keyStorePasswords);
            return this;
        }
        public Builder keyStorePasswords(GetDatabaseToolsConnectionKeyStoreKeyStorePassword... keyStorePasswords) {
            return keyStorePasswords(List.of(keyStorePasswords));
        }
        public Builder keyStoreType(String keyStoreType) {
            this.keyStoreType = Objects.requireNonNull(keyStoreType);
            return this;
        }        public GetDatabaseToolsConnectionKeyStore build() {
            return new GetDatabaseToolsConnectionKeyStore(keyStoreContents, keyStorePasswords, keyStoreType);
        }
    }
}
