// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.OspGateway.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.OspGateway.outputs.SubscriptionSubscriptionPaymentGatewayMerchantDefinedData;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class SubscriptionSubscriptionPaymentGateway {
    /**
     * @return (Updatable) Merchant details.
     * 
     */
    private @Nullable SubscriptionSubscriptionPaymentGatewayMerchantDefinedData merchantDefinedData;

    private SubscriptionSubscriptionPaymentGateway() {}
    /**
     * @return (Updatable) Merchant details.
     * 
     */
    public Optional<SubscriptionSubscriptionPaymentGatewayMerchantDefinedData> merchantDefinedData() {
        return Optional.ofNullable(this.merchantDefinedData);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(SubscriptionSubscriptionPaymentGateway defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable SubscriptionSubscriptionPaymentGatewayMerchantDefinedData merchantDefinedData;
        public Builder() {}
        public Builder(SubscriptionSubscriptionPaymentGateway defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.merchantDefinedData = defaults.merchantDefinedData;
        }

        @CustomType.Setter
        public Builder merchantDefinedData(@Nullable SubscriptionSubscriptionPaymentGatewayMerchantDefinedData merchantDefinedData) {
            this.merchantDefinedData = merchantDefinedData;
            return this;
        }
        public SubscriptionSubscriptionPaymentGateway build() {
            final var o = new SubscriptionSubscriptionPaymentGateway();
            o.merchantDefinedData = merchantDefinedData;
            return o;
        }
    }
}