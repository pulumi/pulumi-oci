// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataSafe.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetTargetDatabaseCredential {
    /**
     * @return The password of the database user.
     * 
     */
    private String password;
    /**
     * @return The database user name.
     * 
     */
    private String userName;

    private GetTargetDatabaseCredential() {}
    /**
     * @return The password of the database user.
     * 
     */
    public String password() {
        return this.password;
    }
    /**
     * @return The database user name.
     * 
     */
    public String userName() {
        return this.userName;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetTargetDatabaseCredential defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String password;
        private String userName;
        public Builder() {}
        public Builder(GetTargetDatabaseCredential defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.password = defaults.password;
    	      this.userName = defaults.userName;
        }

        @CustomType.Setter
        public Builder password(String password) {
            if (password == null) {
              throw new MissingRequiredPropertyException("GetTargetDatabaseCredential", "password");
            }
            this.password = password;
            return this;
        }
        @CustomType.Setter
        public Builder userName(String userName) {
            if (userName == null) {
              throw new MissingRequiredPropertyException("GetTargetDatabaseCredential", "userName");
            }
            this.userName = userName;
            return this;
        }
        public GetTargetDatabaseCredential build() {
            final var _resultValue = new GetTargetDatabaseCredential();
            _resultValue.password = password;
            _resultValue.userName = userName;
            return _resultValue;
        }
    }
}
