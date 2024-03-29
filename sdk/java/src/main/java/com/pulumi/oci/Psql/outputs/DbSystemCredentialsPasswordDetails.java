// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Psql.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class DbSystemCredentialsPasswordDetails {
    /**
     * @return The database system password.
     * 
     */
    private @Nullable String password;
    /**
     * @return The password type.
     * 
     */
    private String passwordType;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the secret where the password is stored.
     * 
     */
    private @Nullable String secretId;
    /**
     * @return The secret version of the stored password.
     * 
     */
    private @Nullable String secretVersion;

    private DbSystemCredentialsPasswordDetails() {}
    /**
     * @return The database system password.
     * 
     */
    public Optional<String> password() {
        return Optional.ofNullable(this.password);
    }
    /**
     * @return The password type.
     * 
     */
    public String passwordType() {
        return this.passwordType;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the secret where the password is stored.
     * 
     */
    public Optional<String> secretId() {
        return Optional.ofNullable(this.secretId);
    }
    /**
     * @return The secret version of the stored password.
     * 
     */
    public Optional<String> secretVersion() {
        return Optional.ofNullable(this.secretVersion);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(DbSystemCredentialsPasswordDetails defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String password;
        private String passwordType;
        private @Nullable String secretId;
        private @Nullable String secretVersion;
        public Builder() {}
        public Builder(DbSystemCredentialsPasswordDetails defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.password = defaults.password;
    	      this.passwordType = defaults.passwordType;
    	      this.secretId = defaults.secretId;
    	      this.secretVersion = defaults.secretVersion;
        }

        @CustomType.Setter
        public Builder password(@Nullable String password) {

            this.password = password;
            return this;
        }
        @CustomType.Setter
        public Builder passwordType(String passwordType) {
            if (passwordType == null) {
              throw new MissingRequiredPropertyException("DbSystemCredentialsPasswordDetails", "passwordType");
            }
            this.passwordType = passwordType;
            return this;
        }
        @CustomType.Setter
        public Builder secretId(@Nullable String secretId) {

            this.secretId = secretId;
            return this;
        }
        @CustomType.Setter
        public Builder secretVersion(@Nullable String secretVersion) {

            this.secretVersion = secretVersion;
            return this;
        }
        public DbSystemCredentialsPasswordDetails build() {
            final var _resultValue = new DbSystemCredentialsPasswordDetails();
            _resultValue.password = password;
            _resultValue.passwordType = passwordType;
            _resultValue.secretId = secretId;
            _resultValue.secretVersion = secretVersion;
            return _resultValue;
        }
    }
}
