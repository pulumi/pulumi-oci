// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.UsageProxy.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class SubscriptionRedeemableUserItem {
    /**
     * @return The email ID for a user that can redeem rewards.
     * 
     */
    private final String emailId;

    @CustomType.Constructor
    private SubscriptionRedeemableUserItem(@CustomType.Parameter("emailId") String emailId) {
        this.emailId = emailId;
    }

    /**
     * @return The email ID for a user that can redeem rewards.
     * 
     */
    public String emailId() {
        return this.emailId;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(SubscriptionRedeemableUserItem defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String emailId;

        public Builder() {
    	      // Empty
        }

        public Builder(SubscriptionRedeemableUserItem defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.emailId = defaults.emailId;
        }

        public Builder emailId(String emailId) {
            this.emailId = Objects.requireNonNull(emailId);
            return this;
        }        public SubscriptionRedeemableUserItem build() {
            return new SubscriptionRedeemableUserItem(emailId);
        }
    }
}
