// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.MeteringComputation.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.MeteringComputation.outputs.UsageItemTag;
import java.lang.Boolean;
import java.lang.Double;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class UsageItem {
    /**
     * @return The availability domain of the usage.
     * 
     */
    private final @Nullable String ad;
    /**
     * @return The compartment OCID.
     * 
     */
    private final @Nullable String compartmentId;
    /**
     * @return The compartment name.
     * 
     */
    private final @Nullable String compartmentName;
    /**
     * @return The compartment path, starting from root.
     * 
     */
    private final @Nullable String compartmentPath;
    /**
     * @return The computed cost.
     * 
     */
    private final @Nullable Double computedAmount;
    /**
     * @return The usage number.
     * 
     */
    private final @Nullable Double computedQuantity;
    /**
     * @return The price currency.
     * 
     */
    private final @Nullable String currency;
    /**
     * @return The discretionary discount applied to the SKU.
     * 
     */
    private final @Nullable Double discount;
    /**
     * @return The forecasted data.
     * 
     */
    private final @Nullable Boolean isForecast;
    /**
     * @return The SKU list rate (not discount).
     * 
     */
    private final @Nullable Double listRate;
    /**
     * @return The overage usage.
     * 
     */
    private final @Nullable String overage;
    /**
     * @return The SPM OverageFlag.
     * 
     */
    private final @Nullable String overagesFlag;
    /**
     * @return Platform for the cost.
     * 
     */
    private final @Nullable String platform;
    /**
     * @return The region of the usage.
     * 
     */
    private final @Nullable String region;
    /**
     * @return The resource OCID that is incurring the cost.
     * 
     */
    private final @Nullable String resourceId;
    /**
     * @return The resource name that is incurring the cost.
     * 
     */
    private final @Nullable String resourceName;
    /**
     * @return The service name that is incurring the cost.
     * 
     */
    private final @Nullable String service;
    /**
     * @return The resource shape.
     * 
     */
    private final @Nullable String shape;
    /**
     * @return The SKU friendly name.
     * 
     */
    private final @Nullable String skuName;
    /**
     * @return The SKU part number.
     * 
     */
    private final @Nullable String skuPartNumber;
    /**
     * @return The subscription ID.
     * 
     */
    private final @Nullable String subscriptionId;
    /**
     * @return For grouping, a tag definition. For filtering, a definition and key.
     * 
     */
    private final @Nullable List<UsageItemTag> tags;
    /**
     * @return Tenant ID.
     * 
     */
    private final @Nullable String tenantId;
    /**
     * @return The tenancy name.
     * 
     */
    private final @Nullable String tenantName;
    /**
     * @return The usage end time.
     * 
     */
    private final @Nullable String timeUsageEnded;
    /**
     * @return The usage start time.
     * 
     */
    private final @Nullable String timeUsageStarted;
    /**
     * @return The usage unit.
     * 
     */
    private final @Nullable String unit;
    /**
     * @return The price per unit.
     * 
     */
    private final @Nullable Double unitPrice;
    /**
     * @return The resource size being metered.
     * 
     */
    private final @Nullable Double weight;

    @CustomType.Constructor
    private UsageItem(
        @CustomType.Parameter("ad") @Nullable String ad,
        @CustomType.Parameter("compartmentId") @Nullable String compartmentId,
        @CustomType.Parameter("compartmentName") @Nullable String compartmentName,
        @CustomType.Parameter("compartmentPath") @Nullable String compartmentPath,
        @CustomType.Parameter("computedAmount") @Nullable Double computedAmount,
        @CustomType.Parameter("computedQuantity") @Nullable Double computedQuantity,
        @CustomType.Parameter("currency") @Nullable String currency,
        @CustomType.Parameter("discount") @Nullable Double discount,
        @CustomType.Parameter("isForecast") @Nullable Boolean isForecast,
        @CustomType.Parameter("listRate") @Nullable Double listRate,
        @CustomType.Parameter("overage") @Nullable String overage,
        @CustomType.Parameter("overagesFlag") @Nullable String overagesFlag,
        @CustomType.Parameter("platform") @Nullable String platform,
        @CustomType.Parameter("region") @Nullable String region,
        @CustomType.Parameter("resourceId") @Nullable String resourceId,
        @CustomType.Parameter("resourceName") @Nullable String resourceName,
        @CustomType.Parameter("service") @Nullable String service,
        @CustomType.Parameter("shape") @Nullable String shape,
        @CustomType.Parameter("skuName") @Nullable String skuName,
        @CustomType.Parameter("skuPartNumber") @Nullable String skuPartNumber,
        @CustomType.Parameter("subscriptionId") @Nullable String subscriptionId,
        @CustomType.Parameter("tags") @Nullable List<UsageItemTag> tags,
        @CustomType.Parameter("tenantId") @Nullable String tenantId,
        @CustomType.Parameter("tenantName") @Nullable String tenantName,
        @CustomType.Parameter("timeUsageEnded") @Nullable String timeUsageEnded,
        @CustomType.Parameter("timeUsageStarted") @Nullable String timeUsageStarted,
        @CustomType.Parameter("unit") @Nullable String unit,
        @CustomType.Parameter("unitPrice") @Nullable Double unitPrice,
        @CustomType.Parameter("weight") @Nullable Double weight) {
        this.ad = ad;
        this.compartmentId = compartmentId;
        this.compartmentName = compartmentName;
        this.compartmentPath = compartmentPath;
        this.computedAmount = computedAmount;
        this.computedQuantity = computedQuantity;
        this.currency = currency;
        this.discount = discount;
        this.isForecast = isForecast;
        this.listRate = listRate;
        this.overage = overage;
        this.overagesFlag = overagesFlag;
        this.platform = platform;
        this.region = region;
        this.resourceId = resourceId;
        this.resourceName = resourceName;
        this.service = service;
        this.shape = shape;
        this.skuName = skuName;
        this.skuPartNumber = skuPartNumber;
        this.subscriptionId = subscriptionId;
        this.tags = tags;
        this.tenantId = tenantId;
        this.tenantName = tenantName;
        this.timeUsageEnded = timeUsageEnded;
        this.timeUsageStarted = timeUsageStarted;
        this.unit = unit;
        this.unitPrice = unitPrice;
        this.weight = weight;
    }

    /**
     * @return The availability domain of the usage.
     * 
     */
    public Optional<String> ad() {
        return Optional.ofNullable(this.ad);
    }
    /**
     * @return The compartment OCID.
     * 
     */
    public Optional<String> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
    }
    /**
     * @return The compartment name.
     * 
     */
    public Optional<String> compartmentName() {
        return Optional.ofNullable(this.compartmentName);
    }
    /**
     * @return The compartment path, starting from root.
     * 
     */
    public Optional<String> compartmentPath() {
        return Optional.ofNullable(this.compartmentPath);
    }
    /**
     * @return The computed cost.
     * 
     */
    public Optional<Double> computedAmount() {
        return Optional.ofNullable(this.computedAmount);
    }
    /**
     * @return The usage number.
     * 
     */
    public Optional<Double> computedQuantity() {
        return Optional.ofNullable(this.computedQuantity);
    }
    /**
     * @return The price currency.
     * 
     */
    public Optional<String> currency() {
        return Optional.ofNullable(this.currency);
    }
    /**
     * @return The discretionary discount applied to the SKU.
     * 
     */
    public Optional<Double> discount() {
        return Optional.ofNullable(this.discount);
    }
    /**
     * @return The forecasted data.
     * 
     */
    public Optional<Boolean> isForecast() {
        return Optional.ofNullable(this.isForecast);
    }
    /**
     * @return The SKU list rate (not discount).
     * 
     */
    public Optional<Double> listRate() {
        return Optional.ofNullable(this.listRate);
    }
    /**
     * @return The overage usage.
     * 
     */
    public Optional<String> overage() {
        return Optional.ofNullable(this.overage);
    }
    /**
     * @return The SPM OverageFlag.
     * 
     */
    public Optional<String> overagesFlag() {
        return Optional.ofNullable(this.overagesFlag);
    }
    /**
     * @return Platform for the cost.
     * 
     */
    public Optional<String> platform() {
        return Optional.ofNullable(this.platform);
    }
    /**
     * @return The region of the usage.
     * 
     */
    public Optional<String> region() {
        return Optional.ofNullable(this.region);
    }
    /**
     * @return The resource OCID that is incurring the cost.
     * 
     */
    public Optional<String> resourceId() {
        return Optional.ofNullable(this.resourceId);
    }
    /**
     * @return The resource name that is incurring the cost.
     * 
     */
    public Optional<String> resourceName() {
        return Optional.ofNullable(this.resourceName);
    }
    /**
     * @return The service name that is incurring the cost.
     * 
     */
    public Optional<String> service() {
        return Optional.ofNullable(this.service);
    }
    /**
     * @return The resource shape.
     * 
     */
    public Optional<String> shape() {
        return Optional.ofNullable(this.shape);
    }
    /**
     * @return The SKU friendly name.
     * 
     */
    public Optional<String> skuName() {
        return Optional.ofNullable(this.skuName);
    }
    /**
     * @return The SKU part number.
     * 
     */
    public Optional<String> skuPartNumber() {
        return Optional.ofNullable(this.skuPartNumber);
    }
    /**
     * @return The subscription ID.
     * 
     */
    public Optional<String> subscriptionId() {
        return Optional.ofNullable(this.subscriptionId);
    }
    /**
     * @return For grouping, a tag definition. For filtering, a definition and key.
     * 
     */
    public List<UsageItemTag> tags() {
        return this.tags == null ? List.of() : this.tags;
    }
    /**
     * @return Tenant ID.
     * 
     */
    public Optional<String> tenantId() {
        return Optional.ofNullable(this.tenantId);
    }
    /**
     * @return The tenancy name.
     * 
     */
    public Optional<String> tenantName() {
        return Optional.ofNullable(this.tenantName);
    }
    /**
     * @return The usage end time.
     * 
     */
    public Optional<String> timeUsageEnded() {
        return Optional.ofNullable(this.timeUsageEnded);
    }
    /**
     * @return The usage start time.
     * 
     */
    public Optional<String> timeUsageStarted() {
        return Optional.ofNullable(this.timeUsageStarted);
    }
    /**
     * @return The usage unit.
     * 
     */
    public Optional<String> unit() {
        return Optional.ofNullable(this.unit);
    }
    /**
     * @return The price per unit.
     * 
     */
    public Optional<Double> unitPrice() {
        return Optional.ofNullable(this.unitPrice);
    }
    /**
     * @return The resource size being metered.
     * 
     */
    public Optional<Double> weight() {
        return Optional.ofNullable(this.weight);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(UsageItem defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private @Nullable String ad;
        private @Nullable String compartmentId;
        private @Nullable String compartmentName;
        private @Nullable String compartmentPath;
        private @Nullable Double computedAmount;
        private @Nullable Double computedQuantity;
        private @Nullable String currency;
        private @Nullable Double discount;
        private @Nullable Boolean isForecast;
        private @Nullable Double listRate;
        private @Nullable String overage;
        private @Nullable String overagesFlag;
        private @Nullable String platform;
        private @Nullable String region;
        private @Nullable String resourceId;
        private @Nullable String resourceName;
        private @Nullable String service;
        private @Nullable String shape;
        private @Nullable String skuName;
        private @Nullable String skuPartNumber;
        private @Nullable String subscriptionId;
        private @Nullable List<UsageItemTag> tags;
        private @Nullable String tenantId;
        private @Nullable String tenantName;
        private @Nullable String timeUsageEnded;
        private @Nullable String timeUsageStarted;
        private @Nullable String unit;
        private @Nullable Double unitPrice;
        private @Nullable Double weight;

        public Builder() {
    	      // Empty
        }

        public Builder(UsageItem defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.ad = defaults.ad;
    	      this.compartmentId = defaults.compartmentId;
    	      this.compartmentName = defaults.compartmentName;
    	      this.compartmentPath = defaults.compartmentPath;
    	      this.computedAmount = defaults.computedAmount;
    	      this.computedQuantity = defaults.computedQuantity;
    	      this.currency = defaults.currency;
    	      this.discount = defaults.discount;
    	      this.isForecast = defaults.isForecast;
    	      this.listRate = defaults.listRate;
    	      this.overage = defaults.overage;
    	      this.overagesFlag = defaults.overagesFlag;
    	      this.platform = defaults.platform;
    	      this.region = defaults.region;
    	      this.resourceId = defaults.resourceId;
    	      this.resourceName = defaults.resourceName;
    	      this.service = defaults.service;
    	      this.shape = defaults.shape;
    	      this.skuName = defaults.skuName;
    	      this.skuPartNumber = defaults.skuPartNumber;
    	      this.subscriptionId = defaults.subscriptionId;
    	      this.tags = defaults.tags;
    	      this.tenantId = defaults.tenantId;
    	      this.tenantName = defaults.tenantName;
    	      this.timeUsageEnded = defaults.timeUsageEnded;
    	      this.timeUsageStarted = defaults.timeUsageStarted;
    	      this.unit = defaults.unit;
    	      this.unitPrice = defaults.unitPrice;
    	      this.weight = defaults.weight;
        }

        public Builder ad(@Nullable String ad) {
            this.ad = ad;
            return this;
        }
        public Builder compartmentId(@Nullable String compartmentId) {
            this.compartmentId = compartmentId;
            return this;
        }
        public Builder compartmentName(@Nullable String compartmentName) {
            this.compartmentName = compartmentName;
            return this;
        }
        public Builder compartmentPath(@Nullable String compartmentPath) {
            this.compartmentPath = compartmentPath;
            return this;
        }
        public Builder computedAmount(@Nullable Double computedAmount) {
            this.computedAmount = computedAmount;
            return this;
        }
        public Builder computedQuantity(@Nullable Double computedQuantity) {
            this.computedQuantity = computedQuantity;
            return this;
        }
        public Builder currency(@Nullable String currency) {
            this.currency = currency;
            return this;
        }
        public Builder discount(@Nullable Double discount) {
            this.discount = discount;
            return this;
        }
        public Builder isForecast(@Nullable Boolean isForecast) {
            this.isForecast = isForecast;
            return this;
        }
        public Builder listRate(@Nullable Double listRate) {
            this.listRate = listRate;
            return this;
        }
        public Builder overage(@Nullable String overage) {
            this.overage = overage;
            return this;
        }
        public Builder overagesFlag(@Nullable String overagesFlag) {
            this.overagesFlag = overagesFlag;
            return this;
        }
        public Builder platform(@Nullable String platform) {
            this.platform = platform;
            return this;
        }
        public Builder region(@Nullable String region) {
            this.region = region;
            return this;
        }
        public Builder resourceId(@Nullable String resourceId) {
            this.resourceId = resourceId;
            return this;
        }
        public Builder resourceName(@Nullable String resourceName) {
            this.resourceName = resourceName;
            return this;
        }
        public Builder service(@Nullable String service) {
            this.service = service;
            return this;
        }
        public Builder shape(@Nullable String shape) {
            this.shape = shape;
            return this;
        }
        public Builder skuName(@Nullable String skuName) {
            this.skuName = skuName;
            return this;
        }
        public Builder skuPartNumber(@Nullable String skuPartNumber) {
            this.skuPartNumber = skuPartNumber;
            return this;
        }
        public Builder subscriptionId(@Nullable String subscriptionId) {
            this.subscriptionId = subscriptionId;
            return this;
        }
        public Builder tags(@Nullable List<UsageItemTag> tags) {
            this.tags = tags;
            return this;
        }
        public Builder tags(UsageItemTag... tags) {
            return tags(List.of(tags));
        }
        public Builder tenantId(@Nullable String tenantId) {
            this.tenantId = tenantId;
            return this;
        }
        public Builder tenantName(@Nullable String tenantName) {
            this.tenantName = tenantName;
            return this;
        }
        public Builder timeUsageEnded(@Nullable String timeUsageEnded) {
            this.timeUsageEnded = timeUsageEnded;
            return this;
        }
        public Builder timeUsageStarted(@Nullable String timeUsageStarted) {
            this.timeUsageStarted = timeUsageStarted;
            return this;
        }
        public Builder unit(@Nullable String unit) {
            this.unit = unit;
            return this;
        }
        public Builder unitPrice(@Nullable Double unitPrice) {
            this.unitPrice = unitPrice;
            return this;
        }
        public Builder weight(@Nullable Double weight) {
            this.weight = weight;
            return this;
        }        public UsageItem build() {
            return new UsageItem(ad, compartmentId, compartmentName, compartmentPath, computedAmount, computedQuantity, currency, discount, isForecast, listRate, overage, overagesFlag, platform, region, resourceId, resourceName, service, shape, skuName, skuPartNumber, subscriptionId, tags, tenantId, tenantName, timeUsageEnded, timeUsageStarted, unit, unitPrice, weight);
        }
    }
}
