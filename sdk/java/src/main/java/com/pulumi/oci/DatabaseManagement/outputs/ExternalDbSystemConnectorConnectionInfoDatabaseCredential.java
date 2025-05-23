// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class ExternalDbSystemConnectorConnectionInfoDatabaseCredential {
    /**
     * @return The type of the credential for tablespace administration tasks.
     * 
     */
    private @Nullable String credentialType;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the named credential where the database password metadata is stored.
     * 
     */
    private @Nullable String namedCredentialId;
    /**
     * @return The database user&#39;s password encoded using BASE64 scheme.
     * 
     */
    private @Nullable String password;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Secret where the database password is stored.
     * 
     */
    private @Nullable String passwordSecretId;
    /**
     * @return The role of the database user.
     * 
     */
    private @Nullable String role;
    /**
     * @return The user to connect to the database.
     * 
     */
    private @Nullable String username;

    private ExternalDbSystemConnectorConnectionInfoDatabaseCredential() {}
    /**
     * @return The type of the credential for tablespace administration tasks.
     * 
     */
    public Optional<String> credentialType() {
        return Optional.ofNullable(this.credentialType);
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the named credential where the database password metadata is stored.
     * 
     */
    public Optional<String> namedCredentialId() {
        return Optional.ofNullable(this.namedCredentialId);
    }
    /**
     * @return The database user&#39;s password encoded using BASE64 scheme.
     * 
     */
    public Optional<String> password() {
        return Optional.ofNullable(this.password);
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Secret where the database password is stored.
     * 
     */
    public Optional<String> passwordSecretId() {
        return Optional.ofNullable(this.passwordSecretId);
    }
    /**
     * @return The role of the database user.
     * 
     */
    public Optional<String> role() {
        return Optional.ofNullable(this.role);
    }
    /**
     * @return The user to connect to the database.
     * 
     */
    public Optional<String> username() {
        return Optional.ofNullable(this.username);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(ExternalDbSystemConnectorConnectionInfoDatabaseCredential defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String credentialType;
        private @Nullable String namedCredentialId;
        private @Nullable String password;
        private @Nullable String passwordSecretId;
        private @Nullable String role;
        private @Nullable String username;
        public Builder() {}
        public Builder(ExternalDbSystemConnectorConnectionInfoDatabaseCredential defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.credentialType = defaults.credentialType;
    	      this.namedCredentialId = defaults.namedCredentialId;
    	      this.password = defaults.password;
    	      this.passwordSecretId = defaults.passwordSecretId;
    	      this.role = defaults.role;
    	      this.username = defaults.username;
        }

        @CustomType.Setter
        public Builder credentialType(@Nullable String credentialType) {

            this.credentialType = credentialType;
            return this;
        }
        @CustomType.Setter
        public Builder namedCredentialId(@Nullable String namedCredentialId) {

            this.namedCredentialId = namedCredentialId;
            return this;
        }
        @CustomType.Setter
        public Builder password(@Nullable String password) {

            this.password = password;
            return this;
        }
        @CustomType.Setter
        public Builder passwordSecretId(@Nullable String passwordSecretId) {

            this.passwordSecretId = passwordSecretId;
            return this;
        }
        @CustomType.Setter
        public Builder role(@Nullable String role) {

            this.role = role;
            return this;
        }
        @CustomType.Setter
        public Builder username(@Nullable String username) {

            this.username = username;
            return this;
        }
        public ExternalDbSystemConnectorConnectionInfoDatabaseCredential build() {
            final var _resultValue = new ExternalDbSystemConnectorConnectionInfoDatabaseCredential();
            _resultValue.credentialType = credentialType;
            _resultValue.namedCredentialId = namedCredentialId;
            _resultValue.password = password;
            _resultValue.passwordSecretId = passwordSecretId;
            _resultValue.role = role;
            _resultValue.username = username;
            return _resultValue;
        }
    }
}
