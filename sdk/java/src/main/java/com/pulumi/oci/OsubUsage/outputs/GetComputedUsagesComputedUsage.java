// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.OsubUsage.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.OsubUsage.outputs.GetComputedUsagesComputedUsageParentProduct;
import com.pulumi.oci.OsubUsage.outputs.GetComputedUsagesComputedUsageProduct;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetComputedUsagesComputedUsage {
    /**
     * @return Subscribed service commitmentId.
     * 
     */
    private final String commitmentServiceId;
    /**
     * @return SPM Internal compute records source .
     * 
     */
    private final String computeSource;
    private final String computedUsageId;
    /**
     * @return Computed Line Amount not rounded
     * 
     */
    private final String cost;
    /**
     * @return Computed Line Amount rounded.
     * 
     */
    private final String costRounded;
    /**
     * @return Currency code
     * 
     */
    private final String currencyCode;
    /**
     * @return Data Center Attribute as sent by MQS to SPM.
     * 
     */
    private final String dataCenter;
    /**
     * @return SPM Internal computed usage Id , 32 character string
     * 
     */
    private final String id;
    /**
     * @return Invoicing status for the aggregated compute usage
     * 
     */
    private final Boolean isInvoiced;
    /**
     * @return MQS Identfier send to SPM , SPM does not transform this attribute and is received as is.
     * 
     */
    private final String mqsMessageId;
    /**
     * @return Net Unit Price for the product in consideration, price actual.
     * 
     */
    private final String netUnitPrice;
    /**
     * @return SPM Internal Original usage Line number identifier in SPM coming from Metered Services entity.
     * 
     */
    private final String originalUsageNumber;
    /**
     * @return Product part number for subscribed service line, called parent product.
     * 
     */
    private final List<GetComputedUsagesComputedUsageParentProduct> parentProducts;
    /**
     * @return Subscribed service line parent id
     * 
     */
    private final String parentSubscribedServiceId;
    /**
     * @return Subscription plan number
     * 
     */
    private final String planNumber;
    /**
     * @return Product description
     * 
     */
    private final List<GetComputedUsagesComputedUsageProduct> products;
    /**
     * @return Total Quantity that was used for computation
     * 
     */
    private final String quantity;
    /**
     * @return Ratecard Id at subscribed service level
     * 
     */
    private final String rateCardId;
    /**
     * @return References the tier in the ratecard for that usage (OCI will be using the same reference to cross-reference for correctness on the usage csv report), comes from Entity OBSCNTR_IPT_PRODUCTTIER.
     * 
     */
    private final String rateCardTierdId;
    /**
     * @return Computed Usage created time, expressed in RFC 3339 timestamp format.
     * 
     */
    private final String timeCreated;
    /**
     * @return Metered Service date, expressed in RFC 3339 timestamp format.
     * 
     */
    private final String timeMeteredOn;
    /**
     * @return Usae computation date, expressed in RFC 3339 timestamp format.
     * 
     */
    private final String timeOfArrival;
    /**
     * @return Computed Usage updated time, expressed in RFC 3339 timestamp format.
     * 
     */
    private final String timeUpdated;
    /**
     * @return Usage compute type in SPM.
     * 
     */
    private final String type;
    /**
     * @return Unit of Messure
     * 
     */
    private final String unitOfMeasure;
    /**
     * @return SPM Internal usage Line number identifier in SPM coming from Metered Services entity.
     * 
     */
    private final String usageNumber;

    @CustomType.Constructor
    private GetComputedUsagesComputedUsage(
        @CustomType.Parameter("commitmentServiceId") String commitmentServiceId,
        @CustomType.Parameter("computeSource") String computeSource,
        @CustomType.Parameter("computedUsageId") String computedUsageId,
        @CustomType.Parameter("cost") String cost,
        @CustomType.Parameter("costRounded") String costRounded,
        @CustomType.Parameter("currencyCode") String currencyCode,
        @CustomType.Parameter("dataCenter") String dataCenter,
        @CustomType.Parameter("id") String id,
        @CustomType.Parameter("isInvoiced") Boolean isInvoiced,
        @CustomType.Parameter("mqsMessageId") String mqsMessageId,
        @CustomType.Parameter("netUnitPrice") String netUnitPrice,
        @CustomType.Parameter("originalUsageNumber") String originalUsageNumber,
        @CustomType.Parameter("parentProducts") List<GetComputedUsagesComputedUsageParentProduct> parentProducts,
        @CustomType.Parameter("parentSubscribedServiceId") String parentSubscribedServiceId,
        @CustomType.Parameter("planNumber") String planNumber,
        @CustomType.Parameter("products") List<GetComputedUsagesComputedUsageProduct> products,
        @CustomType.Parameter("quantity") String quantity,
        @CustomType.Parameter("rateCardId") String rateCardId,
        @CustomType.Parameter("rateCardTierdId") String rateCardTierdId,
        @CustomType.Parameter("timeCreated") String timeCreated,
        @CustomType.Parameter("timeMeteredOn") String timeMeteredOn,
        @CustomType.Parameter("timeOfArrival") String timeOfArrival,
        @CustomType.Parameter("timeUpdated") String timeUpdated,
        @CustomType.Parameter("type") String type,
        @CustomType.Parameter("unitOfMeasure") String unitOfMeasure,
        @CustomType.Parameter("usageNumber") String usageNumber) {
        this.commitmentServiceId = commitmentServiceId;
        this.computeSource = computeSource;
        this.computedUsageId = computedUsageId;
        this.cost = cost;
        this.costRounded = costRounded;
        this.currencyCode = currencyCode;
        this.dataCenter = dataCenter;
        this.id = id;
        this.isInvoiced = isInvoiced;
        this.mqsMessageId = mqsMessageId;
        this.netUnitPrice = netUnitPrice;
        this.originalUsageNumber = originalUsageNumber;
        this.parentProducts = parentProducts;
        this.parentSubscribedServiceId = parentSubscribedServiceId;
        this.planNumber = planNumber;
        this.products = products;
        this.quantity = quantity;
        this.rateCardId = rateCardId;
        this.rateCardTierdId = rateCardTierdId;
        this.timeCreated = timeCreated;
        this.timeMeteredOn = timeMeteredOn;
        this.timeOfArrival = timeOfArrival;
        this.timeUpdated = timeUpdated;
        this.type = type;
        this.unitOfMeasure = unitOfMeasure;
        this.usageNumber = usageNumber;
    }

    /**
     * @return Subscribed service commitmentId.
     * 
     */
    public String commitmentServiceId() {
        return this.commitmentServiceId;
    }
    /**
     * @return SPM Internal compute records source .
     * 
     */
    public String computeSource() {
        return this.computeSource;
    }
    public String computedUsageId() {
        return this.computedUsageId;
    }
    /**
     * @return Computed Line Amount not rounded
     * 
     */
    public String cost() {
        return this.cost;
    }
    /**
     * @return Computed Line Amount rounded.
     * 
     */
    public String costRounded() {
        return this.costRounded;
    }
    /**
     * @return Currency code
     * 
     */
    public String currencyCode() {
        return this.currencyCode;
    }
    /**
     * @return Data Center Attribute as sent by MQS to SPM.
     * 
     */
    public String dataCenter() {
        return this.dataCenter;
    }
    /**
     * @return SPM Internal computed usage Id , 32 character string
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return Invoicing status for the aggregated compute usage
     * 
     */
    public Boolean isInvoiced() {
        return this.isInvoiced;
    }
    /**
     * @return MQS Identfier send to SPM , SPM does not transform this attribute and is received as is.
     * 
     */
    public String mqsMessageId() {
        return this.mqsMessageId;
    }
    /**
     * @return Net Unit Price for the product in consideration, price actual.
     * 
     */
    public String netUnitPrice() {
        return this.netUnitPrice;
    }
    /**
     * @return SPM Internal Original usage Line number identifier in SPM coming from Metered Services entity.
     * 
     */
    public String originalUsageNumber() {
        return this.originalUsageNumber;
    }
    /**
     * @return Product part number for subscribed service line, called parent product.
     * 
     */
    public List<GetComputedUsagesComputedUsageParentProduct> parentProducts() {
        return this.parentProducts;
    }
    /**
     * @return Subscribed service line parent id
     * 
     */
    public String parentSubscribedServiceId() {
        return this.parentSubscribedServiceId;
    }
    /**
     * @return Subscription plan number
     * 
     */
    public String planNumber() {
        return this.planNumber;
    }
    /**
     * @return Product description
     * 
     */
    public List<GetComputedUsagesComputedUsageProduct> products() {
        return this.products;
    }
    /**
     * @return Total Quantity that was used for computation
     * 
     */
    public String quantity() {
        return this.quantity;
    }
    /**
     * @return Ratecard Id at subscribed service level
     * 
     */
    public String rateCardId() {
        return this.rateCardId;
    }
    /**
     * @return References the tier in the ratecard for that usage (OCI will be using the same reference to cross-reference for correctness on the usage csv report), comes from Entity OBSCNTR_IPT_PRODUCTTIER.
     * 
     */
    public String rateCardTierdId() {
        return this.rateCardTierdId;
    }
    /**
     * @return Computed Usage created time, expressed in RFC 3339 timestamp format.
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return Metered Service date, expressed in RFC 3339 timestamp format.
     * 
     */
    public String timeMeteredOn() {
        return this.timeMeteredOn;
    }
    /**
     * @return Usae computation date, expressed in RFC 3339 timestamp format.
     * 
     */
    public String timeOfArrival() {
        return this.timeOfArrival;
    }
    /**
     * @return Computed Usage updated time, expressed in RFC 3339 timestamp format.
     * 
     */
    public String timeUpdated() {
        return this.timeUpdated;
    }
    /**
     * @return Usage compute type in SPM.
     * 
     */
    public String type() {
        return this.type;
    }
    /**
     * @return Unit of Messure
     * 
     */
    public String unitOfMeasure() {
        return this.unitOfMeasure;
    }
    /**
     * @return SPM Internal usage Line number identifier in SPM coming from Metered Services entity.
     * 
     */
    public String usageNumber() {
        return this.usageNumber;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetComputedUsagesComputedUsage defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String commitmentServiceId;
        private String computeSource;
        private String computedUsageId;
        private String cost;
        private String costRounded;
        private String currencyCode;
        private String dataCenter;
        private String id;
        private Boolean isInvoiced;
        private String mqsMessageId;
        private String netUnitPrice;
        private String originalUsageNumber;
        private List<GetComputedUsagesComputedUsageParentProduct> parentProducts;
        private String parentSubscribedServiceId;
        private String planNumber;
        private List<GetComputedUsagesComputedUsageProduct> products;
        private String quantity;
        private String rateCardId;
        private String rateCardTierdId;
        private String timeCreated;
        private String timeMeteredOn;
        private String timeOfArrival;
        private String timeUpdated;
        private String type;
        private String unitOfMeasure;
        private String usageNumber;

        public Builder() {
    	      // Empty
        }

        public Builder(GetComputedUsagesComputedUsage defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.commitmentServiceId = defaults.commitmentServiceId;
    	      this.computeSource = defaults.computeSource;
    	      this.computedUsageId = defaults.computedUsageId;
    	      this.cost = defaults.cost;
    	      this.costRounded = defaults.costRounded;
    	      this.currencyCode = defaults.currencyCode;
    	      this.dataCenter = defaults.dataCenter;
    	      this.id = defaults.id;
    	      this.isInvoiced = defaults.isInvoiced;
    	      this.mqsMessageId = defaults.mqsMessageId;
    	      this.netUnitPrice = defaults.netUnitPrice;
    	      this.originalUsageNumber = defaults.originalUsageNumber;
    	      this.parentProducts = defaults.parentProducts;
    	      this.parentSubscribedServiceId = defaults.parentSubscribedServiceId;
    	      this.planNumber = defaults.planNumber;
    	      this.products = defaults.products;
    	      this.quantity = defaults.quantity;
    	      this.rateCardId = defaults.rateCardId;
    	      this.rateCardTierdId = defaults.rateCardTierdId;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeMeteredOn = defaults.timeMeteredOn;
    	      this.timeOfArrival = defaults.timeOfArrival;
    	      this.timeUpdated = defaults.timeUpdated;
    	      this.type = defaults.type;
    	      this.unitOfMeasure = defaults.unitOfMeasure;
    	      this.usageNumber = defaults.usageNumber;
        }

        public Builder commitmentServiceId(String commitmentServiceId) {
            this.commitmentServiceId = Objects.requireNonNull(commitmentServiceId);
            return this;
        }
        public Builder computeSource(String computeSource) {
            this.computeSource = Objects.requireNonNull(computeSource);
            return this;
        }
        public Builder computedUsageId(String computedUsageId) {
            this.computedUsageId = Objects.requireNonNull(computedUsageId);
            return this;
        }
        public Builder cost(String cost) {
            this.cost = Objects.requireNonNull(cost);
            return this;
        }
        public Builder costRounded(String costRounded) {
            this.costRounded = Objects.requireNonNull(costRounded);
            return this;
        }
        public Builder currencyCode(String currencyCode) {
            this.currencyCode = Objects.requireNonNull(currencyCode);
            return this;
        }
        public Builder dataCenter(String dataCenter) {
            this.dataCenter = Objects.requireNonNull(dataCenter);
            return this;
        }
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        public Builder isInvoiced(Boolean isInvoiced) {
            this.isInvoiced = Objects.requireNonNull(isInvoiced);
            return this;
        }
        public Builder mqsMessageId(String mqsMessageId) {
            this.mqsMessageId = Objects.requireNonNull(mqsMessageId);
            return this;
        }
        public Builder netUnitPrice(String netUnitPrice) {
            this.netUnitPrice = Objects.requireNonNull(netUnitPrice);
            return this;
        }
        public Builder originalUsageNumber(String originalUsageNumber) {
            this.originalUsageNumber = Objects.requireNonNull(originalUsageNumber);
            return this;
        }
        public Builder parentProducts(List<GetComputedUsagesComputedUsageParentProduct> parentProducts) {
            this.parentProducts = Objects.requireNonNull(parentProducts);
            return this;
        }
        public Builder parentProducts(GetComputedUsagesComputedUsageParentProduct... parentProducts) {
            return parentProducts(List.of(parentProducts));
        }
        public Builder parentSubscribedServiceId(String parentSubscribedServiceId) {
            this.parentSubscribedServiceId = Objects.requireNonNull(parentSubscribedServiceId);
            return this;
        }
        public Builder planNumber(String planNumber) {
            this.planNumber = Objects.requireNonNull(planNumber);
            return this;
        }
        public Builder products(List<GetComputedUsagesComputedUsageProduct> products) {
            this.products = Objects.requireNonNull(products);
            return this;
        }
        public Builder products(GetComputedUsagesComputedUsageProduct... products) {
            return products(List.of(products));
        }
        public Builder quantity(String quantity) {
            this.quantity = Objects.requireNonNull(quantity);
            return this;
        }
        public Builder rateCardId(String rateCardId) {
            this.rateCardId = Objects.requireNonNull(rateCardId);
            return this;
        }
        public Builder rateCardTierdId(String rateCardTierdId) {
            this.rateCardTierdId = Objects.requireNonNull(rateCardTierdId);
            return this;
        }
        public Builder timeCreated(String timeCreated) {
            this.timeCreated = Objects.requireNonNull(timeCreated);
            return this;
        }
        public Builder timeMeteredOn(String timeMeteredOn) {
            this.timeMeteredOn = Objects.requireNonNull(timeMeteredOn);
            return this;
        }
        public Builder timeOfArrival(String timeOfArrival) {
            this.timeOfArrival = Objects.requireNonNull(timeOfArrival);
            return this;
        }
        public Builder timeUpdated(String timeUpdated) {
            this.timeUpdated = Objects.requireNonNull(timeUpdated);
            return this;
        }
        public Builder type(String type) {
            this.type = Objects.requireNonNull(type);
            return this;
        }
        public Builder unitOfMeasure(String unitOfMeasure) {
            this.unitOfMeasure = Objects.requireNonNull(unitOfMeasure);
            return this;
        }
        public Builder usageNumber(String usageNumber) {
            this.usageNumber = Objects.requireNonNull(usageNumber);
            return this;
        }        public GetComputedUsagesComputedUsage build() {
            return new GetComputedUsagesComputedUsage(commitmentServiceId, computeSource, computedUsageId, cost, costRounded, currencyCode, dataCenter, id, isInvoiced, mqsMessageId, netUnitPrice, originalUsageNumber, parentProducts, parentSubscribedServiceId, planNumber, products, quantity, rateCardId, rateCardTierdId, timeCreated, timeMeteredOn, timeOfArrival, timeUpdated, type, unitOfMeasure, usageNumber);
        }
    }
}
