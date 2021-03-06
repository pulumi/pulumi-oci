// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.OspGateway.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.OspGateway.outputs.GetSubscriptionSubscriptionPaymentGatewayMerchantDefinedData;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetSubscriptionSubscriptionPaymentGateway {
    /**
     * @return Merchant details.
     * 
     */
    private final List<GetSubscriptionSubscriptionPaymentGatewayMerchantDefinedData> merchantDefinedDatas;

    @CustomType.Constructor
    private GetSubscriptionSubscriptionPaymentGateway(@CustomType.Parameter("merchantDefinedDatas") List<GetSubscriptionSubscriptionPaymentGatewayMerchantDefinedData> merchantDefinedDatas) {
        this.merchantDefinedDatas = merchantDefinedDatas;
    }

    /**
     * @return Merchant details.
     * 
     */
    public List<GetSubscriptionSubscriptionPaymentGatewayMerchantDefinedData> merchantDefinedDatas() {
        return this.merchantDefinedDatas;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetSubscriptionSubscriptionPaymentGateway defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private List<GetSubscriptionSubscriptionPaymentGatewayMerchantDefinedData> merchantDefinedDatas;

        public Builder() {
    	      // Empty
        }

        public Builder(GetSubscriptionSubscriptionPaymentGateway defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.merchantDefinedDatas = defaults.merchantDefinedDatas;
        }

        public Builder merchantDefinedDatas(List<GetSubscriptionSubscriptionPaymentGatewayMerchantDefinedData> merchantDefinedDatas) {
            this.merchantDefinedDatas = Objects.requireNonNull(merchantDefinedDatas);
            return this;
        }
        public Builder merchantDefinedDatas(GetSubscriptionSubscriptionPaymentGatewayMerchantDefinedData... merchantDefinedDatas) {
            return merchantDefinedDatas(List.of(merchantDefinedDatas));
        }        public GetSubscriptionSubscriptionPaymentGateway build() {
            return new GetSubscriptionSubscriptionPaymentGateway(merchantDefinedDatas);
        }
    }
}
