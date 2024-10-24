// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.UsageProxy.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class SubscriptionRedeemableUserItem {
    /**
     * @return The email ID for a user that can redeem rewards.
     * 
     */
    private String emailId;
    /**
     * @return The first name of the user that can redeem rewards.
     * 
     */
    private @Nullable String firstName;
    /**
     * @return The last name of the user that can redeem rewards.
     * 
     */
    private @Nullable String lastName;

    private SubscriptionRedeemableUserItem() {}
    /**
     * @return The email ID for a user that can redeem rewards.
     * 
     */
    public String emailId() {
        return this.emailId;
    }
    /**
     * @return The first name of the user that can redeem rewards.
     * 
     */
    public Optional<String> firstName() {
        return Optional.ofNullable(this.firstName);
    }
    /**
     * @return The last name of the user that can redeem rewards.
     * 
     */
    public Optional<String> lastName() {
        return Optional.ofNullable(this.lastName);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(SubscriptionRedeemableUserItem defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String emailId;
        private @Nullable String firstName;
        private @Nullable String lastName;
        public Builder() {}
        public Builder(SubscriptionRedeemableUserItem defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.emailId = defaults.emailId;
    	      this.firstName = defaults.firstName;
    	      this.lastName = defaults.lastName;
        }

        @CustomType.Setter
        public Builder emailId(String emailId) {
            if (emailId == null) {
              throw new MissingRequiredPropertyException("SubscriptionRedeemableUserItem", "emailId");
            }
            this.emailId = emailId;
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
        public SubscriptionRedeemableUserItem build() {
            final var _resultValue = new SubscriptionRedeemableUserItem();
            _resultValue.emailId = emailId;
            _resultValue.firstName = firstName;
            _resultValue.lastName = lastName;
            return _resultValue;
        }
    }
}
