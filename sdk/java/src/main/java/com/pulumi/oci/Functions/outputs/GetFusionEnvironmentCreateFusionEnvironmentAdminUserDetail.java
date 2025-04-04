// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Functions.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetFusionEnvironmentCreateFusionEnvironmentAdminUserDetail {
    private String emailAddress;
    private String firstName;
    private String lastName;
    private String password;
    private String username;

    private GetFusionEnvironmentCreateFusionEnvironmentAdminUserDetail() {}
    public String emailAddress() {
        return this.emailAddress;
    }
    public String firstName() {
        return this.firstName;
    }
    public String lastName() {
        return this.lastName;
    }
    public String password() {
        return this.password;
    }
    public String username() {
        return this.username;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetFusionEnvironmentCreateFusionEnvironmentAdminUserDetail defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String emailAddress;
        private String firstName;
        private String lastName;
        private String password;
        private String username;
        public Builder() {}
        public Builder(GetFusionEnvironmentCreateFusionEnvironmentAdminUserDetail defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.emailAddress = defaults.emailAddress;
    	      this.firstName = defaults.firstName;
    	      this.lastName = defaults.lastName;
    	      this.password = defaults.password;
    	      this.username = defaults.username;
        }

        @CustomType.Setter
        public Builder emailAddress(String emailAddress) {
            if (emailAddress == null) {
              throw new MissingRequiredPropertyException("GetFusionEnvironmentCreateFusionEnvironmentAdminUserDetail", "emailAddress");
            }
            this.emailAddress = emailAddress;
            return this;
        }
        @CustomType.Setter
        public Builder firstName(String firstName) {
            if (firstName == null) {
              throw new MissingRequiredPropertyException("GetFusionEnvironmentCreateFusionEnvironmentAdminUserDetail", "firstName");
            }
            this.firstName = firstName;
            return this;
        }
        @CustomType.Setter
        public Builder lastName(String lastName) {
            if (lastName == null) {
              throw new MissingRequiredPropertyException("GetFusionEnvironmentCreateFusionEnvironmentAdminUserDetail", "lastName");
            }
            this.lastName = lastName;
            return this;
        }
        @CustomType.Setter
        public Builder password(String password) {
            if (password == null) {
              throw new MissingRequiredPropertyException("GetFusionEnvironmentCreateFusionEnvironmentAdminUserDetail", "password");
            }
            this.password = password;
            return this;
        }
        @CustomType.Setter
        public Builder username(String username) {
            if (username == null) {
              throw new MissingRequiredPropertyException("GetFusionEnvironmentCreateFusionEnvironmentAdminUserDetail", "username");
            }
            this.username = username;
            return this;
        }
        public GetFusionEnvironmentCreateFusionEnvironmentAdminUserDetail build() {
            final var _resultValue = new GetFusionEnvironmentCreateFusionEnvironmentAdminUserDetail();
            _resultValue.emailAddress = emailAddress;
            _resultValue.firstName = firstName;
            _resultValue.lastName = lastName;
            _resultValue.password = password;
            _resultValue.username = username;
            return _resultValue;
        }
    }
}
