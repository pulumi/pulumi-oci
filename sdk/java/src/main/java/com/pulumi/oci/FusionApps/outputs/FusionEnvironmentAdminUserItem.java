// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.FusionApps.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class FusionEnvironmentAdminUserItem {
    /**
     * @return The email address for the administrator.
     * 
     */
    private @Nullable String emailAddress;
    /**
     * @return The administrator&#39;s first name.
     * 
     */
    private @Nullable String firstName;
    /**
     * @return The administrator&#39;s last name.
     * 
     */
    private @Nullable String lastName;
    /**
     * @return The username for the administrator.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    private @Nullable String username;

    private FusionEnvironmentAdminUserItem() {}
    /**
     * @return The email address for the administrator.
     * 
     */
    public Optional<String> emailAddress() {
        return Optional.ofNullable(this.emailAddress);
    }
    /**
     * @return The administrator&#39;s first name.
     * 
     */
    public Optional<String> firstName() {
        return Optional.ofNullable(this.firstName);
    }
    /**
     * @return The administrator&#39;s last name.
     * 
     */
    public Optional<String> lastName() {
        return Optional.ofNullable(this.lastName);
    }
    /**
     * @return The username for the administrator.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Optional<String> username() {
        return Optional.ofNullable(this.username);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(FusionEnvironmentAdminUserItem defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String emailAddress;
        private @Nullable String firstName;
        private @Nullable String lastName;
        private @Nullable String username;
        public Builder() {}
        public Builder(FusionEnvironmentAdminUserItem defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.emailAddress = defaults.emailAddress;
    	      this.firstName = defaults.firstName;
    	      this.lastName = defaults.lastName;
    	      this.username = defaults.username;
        }

        @CustomType.Setter
        public Builder emailAddress(@Nullable String emailAddress) {

            this.emailAddress = emailAddress;
            return this;
        }
        @CustomType.Setter
        public Builder firstName(@Nullable String firstName) {

            this.firstName = firstName;
            return this;
        }
        @CustomType.Setter
        public Builder lastName(@Nullable String lastName) {

            this.lastName = lastName;
            return this;
        }
        @CustomType.Setter
        public Builder username(@Nullable String username) {

            this.username = username;
            return this;
        }
        public FusionEnvironmentAdminUserItem build() {
            final var _resultValue = new FusionEnvironmentAdminUserItem();
            _resultValue.emailAddress = emailAddress;
            _resultValue.firstName = firstName;
            _resultValue.lastName = lastName;
            _resultValue.username = username;
            return _resultValue;
        }
    }
}
