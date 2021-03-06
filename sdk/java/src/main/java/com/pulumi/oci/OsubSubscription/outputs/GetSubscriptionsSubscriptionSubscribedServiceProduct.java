// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.OsubSubscription.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetSubscriptionsSubscriptionSubscribedServiceProduct {
    /**
     * @return Product name
     * 
     */
    private final String name;
    /**
     * @return Product part numner
     * 
     */
    private final String partNumber;
    /**
     * @return Product provisioning group
     * 
     */
    private final String provisioningGroup;
    /**
     * @return Unit of measure
     * 
     */
    private final String unitOfMeasure;

    @CustomType.Constructor
    private GetSubscriptionsSubscriptionSubscribedServiceProduct(
        @CustomType.Parameter("name") String name,
        @CustomType.Parameter("partNumber") String partNumber,
        @CustomType.Parameter("provisioningGroup") String provisioningGroup,
        @CustomType.Parameter("unitOfMeasure") String unitOfMeasure) {
        this.name = name;
        this.partNumber = partNumber;
        this.provisioningGroup = provisioningGroup;
        this.unitOfMeasure = unitOfMeasure;
    }

    /**
     * @return Product name
     * 
     */
    public String name() {
        return this.name;
    }
    /**
     * @return Product part numner
     * 
     */
    public String partNumber() {
        return this.partNumber;
    }
    /**
     * @return Product provisioning group
     * 
     */
    public String provisioningGroup() {
        return this.provisioningGroup;
    }
    /**
     * @return Unit of measure
     * 
     */
    public String unitOfMeasure() {
        return this.unitOfMeasure;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetSubscriptionsSubscriptionSubscribedServiceProduct defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String name;
        private String partNumber;
        private String provisioningGroup;
        private String unitOfMeasure;

        public Builder() {
    	      // Empty
        }

        public Builder(GetSubscriptionsSubscriptionSubscribedServiceProduct defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.name = defaults.name;
    	      this.partNumber = defaults.partNumber;
    	      this.provisioningGroup = defaults.provisioningGroup;
    	      this.unitOfMeasure = defaults.unitOfMeasure;
        }

        public Builder name(String name) {
            this.name = Objects.requireNonNull(name);
            return this;
        }
        public Builder partNumber(String partNumber) {
            this.partNumber = Objects.requireNonNull(partNumber);
            return this;
        }
        public Builder provisioningGroup(String provisioningGroup) {
            this.provisioningGroup = Objects.requireNonNull(provisioningGroup);
            return this;
        }
        public Builder unitOfMeasure(String unitOfMeasure) {
            this.unitOfMeasure = Objects.requireNonNull(unitOfMeasure);
            return this;
        }        public GetSubscriptionsSubscriptionSubscribedServiceProduct build() {
            return new GetSubscriptionsSubscriptionSubscribedServiceProduct(name, partNumber, provisioningGroup, unitOfMeasure);
        }
    }
}
