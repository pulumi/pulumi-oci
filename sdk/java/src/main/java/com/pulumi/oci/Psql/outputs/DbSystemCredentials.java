// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Psql.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Psql.outputs.DbSystemCredentialsPasswordDetails;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class DbSystemCredentials {
    /**
     * @return Details for the database system password. Password can be passed as `VaultSecretPasswordDetails` or `PlainTextPasswordDetails`.
     * 
     */
    private DbSystemCredentialsPasswordDetails passwordDetails;
    /**
     * @return The database system administrator username.
     * 
     */
    private String username;

    private DbSystemCredentials() {}
    /**
     * @return Details for the database system password. Password can be passed as `VaultSecretPasswordDetails` or `PlainTextPasswordDetails`.
     * 
     */
    public DbSystemCredentialsPasswordDetails passwordDetails() {
        return this.passwordDetails;
    }
    /**
     * @return The database system administrator username.
     * 
     */
    public String username() {
        return this.username;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(DbSystemCredentials defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private DbSystemCredentialsPasswordDetails passwordDetails;
        private String username;
        public Builder() {}
        public Builder(DbSystemCredentials defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.passwordDetails = defaults.passwordDetails;
    	      this.username = defaults.username;
        }

        @CustomType.Setter
        public Builder passwordDetails(DbSystemCredentialsPasswordDetails passwordDetails) {
            if (passwordDetails == null) {
              throw new MissingRequiredPropertyException("DbSystemCredentials", "passwordDetails");
            }
            this.passwordDetails = passwordDetails;
            return this;
        }
        @CustomType.Setter
        public Builder username(String username) {
            if (username == null) {
              throw new MissingRequiredPropertyException("DbSystemCredentials", "username");
            }
            this.username = username;
            return this;
        }
        public DbSystemCredentials build() {
            final var _resultValue = new DbSystemCredentials();
            _resultValue.passwordDetails = passwordDetails;
            _resultValue.username = username;
            return _resultValue;
        }
    }
}
