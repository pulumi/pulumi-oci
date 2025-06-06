// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Tenantmanagercontrolplane.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Tenantmanagercontrolplane.outputs.GetAssignedSubscriptionsAssignedSubscriptionCollectionItemPromotion;
import com.pulumi.oci.Tenantmanagercontrolplane.outputs.GetAssignedSubscriptionsAssignedSubscriptionCollectionItemSkus;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetAssignedSubscriptionsAssignedSubscriptionCollectionItem {
    /**
     * @return Subscription ID.
     * 
     */
    private String classicSubscriptionId;
    /**
     * @return The currency code for the customer associated with the subscription.
     * 
     */
    private String cloudAmountCurrency;
    /**
     * @return The ID of the compartment in which to list resources.
     * 
     */
    private String compartmentId;
    /**
     * @return Customer service identifier for the customer associated with the subscription.
     * 
     */
    private String csiNumber;
    /**
     * @return Currency code. For example USD, MXN.
     * 
     */
    private String currencyCode;
    /**
     * @return The country code for the customer associated with the subscription.
     * 
     */
    private String customerCountryCode;
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    private Map<String,String> definedTags;
    /**
     * @return Date and time when the SKU ended.
     * 
     */
    private String endDate;
    /**
     * @return The version of the subscription entity.
     * 
     */
    private String entityVersion;
    /**
     * @return Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    private Map<String,String> freeformTags;
    /**
     * @return The Oracle ID ([OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)) of the subscription.
     * 
     */
    private String id;
    /**
     * @return Specifies whether or not the subscription is legacy.
     * 
     */
    private Boolean isClassicSubscription;
    /**
     * @return Specifies whether or not the subscription is a government subscription.
     * 
     */
    private Boolean isGovernmentSubscription;
    /**
     * @return Service or component which is used to provision and manage the subscription.
     * 
     */
    private String managedBy;
    /**
     * @return List of subscription order OCIDs that contributed to this subscription.
     * 
     */
    private List<String> orderIds;
    /**
     * @return Specifies any program that is associated with the subscription.
     * 
     */
    private String programType;
    /**
     * @return List of promotions related to the subscription.
     * 
     */
    private List<GetAssignedSubscriptionsAssignedSubscriptionCollectionItemPromotion> promotions;
    /**
     * @return Purchase entitlement ID associated with the subscription.
     * 
     */
    private String purchaseEntitlementId;
    /**
     * @return Region for the subscription.
     * 
     */
    private String regionAssignment;
    /**
     * @return The type of subscription, such as &#39;UCM&#39;, &#39;SAAS&#39;, &#39;ERP&#39;, &#39;CRM&#39;.
     * 
     */
    private String serviceName;
    /**
     * @return List of SKUs linked to the subscription.
     * 
     */
    private List<GetAssignedSubscriptionsAssignedSubscriptionCollectionItemSkus> skuses;
    /**
     * @return Subscription start time.
     * 
     */
    private String startDate;
    /**
     * @return Lifecycle state of the subscription.
     * 
     */
    private String state;
    /**
     * @return Unique Oracle Cloud Subscriptions identifier that is immutable on creation.
     * 
     */
    private String subscriptionNumber;
    /**
     * @return Tier for the subscription, whether a free promotion subscription or a paid subscription.
     * 
     */
    private String subscriptionTier;
    /**
     * @return The date and time of creation, as described in [RFC 3339](https://tools.ietf.org/rfc/rfc3339), section 14.29.
     * 
     */
    private String timeCreated;
    /**
     * @return The date and time of update, as described in [RFC 3339](https://tools.ietf.org/rfc/rfc3339), section 14.29.
     * 
     */
    private String timeUpdated;

    private GetAssignedSubscriptionsAssignedSubscriptionCollectionItem() {}
    /**
     * @return Subscription ID.
     * 
     */
    public String classicSubscriptionId() {
        return this.classicSubscriptionId;
    }
    /**
     * @return The currency code for the customer associated with the subscription.
     * 
     */
    public String cloudAmountCurrency() {
        return this.cloudAmountCurrency;
    }
    /**
     * @return The ID of the compartment in which to list resources.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return Customer service identifier for the customer associated with the subscription.
     * 
     */
    public String csiNumber() {
        return this.csiNumber;
    }
    /**
     * @return Currency code. For example USD, MXN.
     * 
     */
    public String currencyCode() {
        return this.currencyCode;
    }
    /**
     * @return The country code for the customer associated with the subscription.
     * 
     */
    public String customerCountryCode() {
        return this.customerCountryCode;
    }
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Map<String,String> definedTags() {
        return this.definedTags;
    }
    /**
     * @return Date and time when the SKU ended.
     * 
     */
    public String endDate() {
        return this.endDate;
    }
    /**
     * @return The version of the subscription entity.
     * 
     */
    public String entityVersion() {
        return this.entityVersion;
    }
    /**
     * @return Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Map<String,String> freeformTags() {
        return this.freeformTags;
    }
    /**
     * @return The Oracle ID ([OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)) of the subscription.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return Specifies whether or not the subscription is legacy.
     * 
     */
    public Boolean isClassicSubscription() {
        return this.isClassicSubscription;
    }
    /**
     * @return Specifies whether or not the subscription is a government subscription.
     * 
     */
    public Boolean isGovernmentSubscription() {
        return this.isGovernmentSubscription;
    }
    /**
     * @return Service or component which is used to provision and manage the subscription.
     * 
     */
    public String managedBy() {
        return this.managedBy;
    }
    /**
     * @return List of subscription order OCIDs that contributed to this subscription.
     * 
     */
    public List<String> orderIds() {
        return this.orderIds;
    }
    /**
     * @return Specifies any program that is associated with the subscription.
     * 
     */
    public String programType() {
        return this.programType;
    }
    /**
     * @return List of promotions related to the subscription.
     * 
     */
    public List<GetAssignedSubscriptionsAssignedSubscriptionCollectionItemPromotion> promotions() {
        return this.promotions;
    }
    /**
     * @return Purchase entitlement ID associated with the subscription.
     * 
     */
    public String purchaseEntitlementId() {
        return this.purchaseEntitlementId;
    }
    /**
     * @return Region for the subscription.
     * 
     */
    public String regionAssignment() {
        return this.regionAssignment;
    }
    /**
     * @return The type of subscription, such as &#39;UCM&#39;, &#39;SAAS&#39;, &#39;ERP&#39;, &#39;CRM&#39;.
     * 
     */
    public String serviceName() {
        return this.serviceName;
    }
    /**
     * @return List of SKUs linked to the subscription.
     * 
     */
    public List<GetAssignedSubscriptionsAssignedSubscriptionCollectionItemSkus> skuses() {
        return this.skuses;
    }
    /**
     * @return Subscription start time.
     * 
     */
    public String startDate() {
        return this.startDate;
    }
    /**
     * @return Lifecycle state of the subscription.
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return Unique Oracle Cloud Subscriptions identifier that is immutable on creation.
     * 
     */
    public String subscriptionNumber() {
        return this.subscriptionNumber;
    }
    /**
     * @return Tier for the subscription, whether a free promotion subscription or a paid subscription.
     * 
     */
    public String subscriptionTier() {
        return this.subscriptionTier;
    }
    /**
     * @return The date and time of creation, as described in [RFC 3339](https://tools.ietf.org/rfc/rfc3339), section 14.29.
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return The date and time of update, as described in [RFC 3339](https://tools.ietf.org/rfc/rfc3339), section 14.29.
     * 
     */
    public String timeUpdated() {
        return this.timeUpdated;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetAssignedSubscriptionsAssignedSubscriptionCollectionItem defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String classicSubscriptionId;
        private String cloudAmountCurrency;
        private String compartmentId;
        private String csiNumber;
        private String currencyCode;
        private String customerCountryCode;
        private Map<String,String> definedTags;
        private String endDate;
        private String entityVersion;
        private Map<String,String> freeformTags;
        private String id;
        private Boolean isClassicSubscription;
        private Boolean isGovernmentSubscription;
        private String managedBy;
        private List<String> orderIds;
        private String programType;
        private List<GetAssignedSubscriptionsAssignedSubscriptionCollectionItemPromotion> promotions;
        private String purchaseEntitlementId;
        private String regionAssignment;
        private String serviceName;
        private List<GetAssignedSubscriptionsAssignedSubscriptionCollectionItemSkus> skuses;
        private String startDate;
        private String state;
        private String subscriptionNumber;
        private String subscriptionTier;
        private String timeCreated;
        private String timeUpdated;
        public Builder() {}
        public Builder(GetAssignedSubscriptionsAssignedSubscriptionCollectionItem defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.classicSubscriptionId = defaults.classicSubscriptionId;
    	      this.cloudAmountCurrency = defaults.cloudAmountCurrency;
    	      this.compartmentId = defaults.compartmentId;
    	      this.csiNumber = defaults.csiNumber;
    	      this.currencyCode = defaults.currencyCode;
    	      this.customerCountryCode = defaults.customerCountryCode;
    	      this.definedTags = defaults.definedTags;
    	      this.endDate = defaults.endDate;
    	      this.entityVersion = defaults.entityVersion;
    	      this.freeformTags = defaults.freeformTags;
    	      this.id = defaults.id;
    	      this.isClassicSubscription = defaults.isClassicSubscription;
    	      this.isGovernmentSubscription = defaults.isGovernmentSubscription;
    	      this.managedBy = defaults.managedBy;
    	      this.orderIds = defaults.orderIds;
    	      this.programType = defaults.programType;
    	      this.promotions = defaults.promotions;
    	      this.purchaseEntitlementId = defaults.purchaseEntitlementId;
    	      this.regionAssignment = defaults.regionAssignment;
    	      this.serviceName = defaults.serviceName;
    	      this.skuses = defaults.skuses;
    	      this.startDate = defaults.startDate;
    	      this.state = defaults.state;
    	      this.subscriptionNumber = defaults.subscriptionNumber;
    	      this.subscriptionTier = defaults.subscriptionTier;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeUpdated = defaults.timeUpdated;
        }

        @CustomType.Setter
        public Builder classicSubscriptionId(String classicSubscriptionId) {
            if (classicSubscriptionId == null) {
              throw new MissingRequiredPropertyException("GetAssignedSubscriptionsAssignedSubscriptionCollectionItem", "classicSubscriptionId");
            }
            this.classicSubscriptionId = classicSubscriptionId;
            return this;
        }
        @CustomType.Setter
        public Builder cloudAmountCurrency(String cloudAmountCurrency) {
            if (cloudAmountCurrency == null) {
              throw new MissingRequiredPropertyException("GetAssignedSubscriptionsAssignedSubscriptionCollectionItem", "cloudAmountCurrency");
            }
            this.cloudAmountCurrency = cloudAmountCurrency;
            return this;
        }
        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            if (compartmentId == null) {
              throw new MissingRequiredPropertyException("GetAssignedSubscriptionsAssignedSubscriptionCollectionItem", "compartmentId");
            }
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder csiNumber(String csiNumber) {
            if (csiNumber == null) {
              throw new MissingRequiredPropertyException("GetAssignedSubscriptionsAssignedSubscriptionCollectionItem", "csiNumber");
            }
            this.csiNumber = csiNumber;
            return this;
        }
        @CustomType.Setter
        public Builder currencyCode(String currencyCode) {
            if (currencyCode == null) {
              throw new MissingRequiredPropertyException("GetAssignedSubscriptionsAssignedSubscriptionCollectionItem", "currencyCode");
            }
            this.currencyCode = currencyCode;
            return this;
        }
        @CustomType.Setter
        public Builder customerCountryCode(String customerCountryCode) {
            if (customerCountryCode == null) {
              throw new MissingRequiredPropertyException("GetAssignedSubscriptionsAssignedSubscriptionCollectionItem", "customerCountryCode");
            }
            this.customerCountryCode = customerCountryCode;
            return this;
        }
        @CustomType.Setter
        public Builder definedTags(Map<String,String> definedTags) {
            if (definedTags == null) {
              throw new MissingRequiredPropertyException("GetAssignedSubscriptionsAssignedSubscriptionCollectionItem", "definedTags");
            }
            this.definedTags = definedTags;
            return this;
        }
        @CustomType.Setter
        public Builder endDate(String endDate) {
            if (endDate == null) {
              throw new MissingRequiredPropertyException("GetAssignedSubscriptionsAssignedSubscriptionCollectionItem", "endDate");
            }
            this.endDate = endDate;
            return this;
        }
        @CustomType.Setter
        public Builder entityVersion(String entityVersion) {
            if (entityVersion == null) {
              throw new MissingRequiredPropertyException("GetAssignedSubscriptionsAssignedSubscriptionCollectionItem", "entityVersion");
            }
            this.entityVersion = entityVersion;
            return this;
        }
        @CustomType.Setter
        public Builder freeformTags(Map<String,String> freeformTags) {
            if (freeformTags == null) {
              throw new MissingRequiredPropertyException("GetAssignedSubscriptionsAssignedSubscriptionCollectionItem", "freeformTags");
            }
            this.freeformTags = freeformTags;
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetAssignedSubscriptionsAssignedSubscriptionCollectionItem", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder isClassicSubscription(Boolean isClassicSubscription) {
            if (isClassicSubscription == null) {
              throw new MissingRequiredPropertyException("GetAssignedSubscriptionsAssignedSubscriptionCollectionItem", "isClassicSubscription");
            }
            this.isClassicSubscription = isClassicSubscription;
            return this;
        }
        @CustomType.Setter
        public Builder isGovernmentSubscription(Boolean isGovernmentSubscription) {
            if (isGovernmentSubscription == null) {
              throw new MissingRequiredPropertyException("GetAssignedSubscriptionsAssignedSubscriptionCollectionItem", "isGovernmentSubscription");
            }
            this.isGovernmentSubscription = isGovernmentSubscription;
            return this;
        }
        @CustomType.Setter
        public Builder managedBy(String managedBy) {
            if (managedBy == null) {
              throw new MissingRequiredPropertyException("GetAssignedSubscriptionsAssignedSubscriptionCollectionItem", "managedBy");
            }
            this.managedBy = managedBy;
            return this;
        }
        @CustomType.Setter
        public Builder orderIds(List<String> orderIds) {
            if (orderIds == null) {
              throw new MissingRequiredPropertyException("GetAssignedSubscriptionsAssignedSubscriptionCollectionItem", "orderIds");
            }
            this.orderIds = orderIds;
            return this;
        }
        public Builder orderIds(String... orderIds) {
            return orderIds(List.of(orderIds));
        }
        @CustomType.Setter
        public Builder programType(String programType) {
            if (programType == null) {
              throw new MissingRequiredPropertyException("GetAssignedSubscriptionsAssignedSubscriptionCollectionItem", "programType");
            }
            this.programType = programType;
            return this;
        }
        @CustomType.Setter
        public Builder promotions(List<GetAssignedSubscriptionsAssignedSubscriptionCollectionItemPromotion> promotions) {
            if (promotions == null) {
              throw new MissingRequiredPropertyException("GetAssignedSubscriptionsAssignedSubscriptionCollectionItem", "promotions");
            }
            this.promotions = promotions;
            return this;
        }
        public Builder promotions(GetAssignedSubscriptionsAssignedSubscriptionCollectionItemPromotion... promotions) {
            return promotions(List.of(promotions));
        }
        @CustomType.Setter
        public Builder purchaseEntitlementId(String purchaseEntitlementId) {
            if (purchaseEntitlementId == null) {
              throw new MissingRequiredPropertyException("GetAssignedSubscriptionsAssignedSubscriptionCollectionItem", "purchaseEntitlementId");
            }
            this.purchaseEntitlementId = purchaseEntitlementId;
            return this;
        }
        @CustomType.Setter
        public Builder regionAssignment(String regionAssignment) {
            if (regionAssignment == null) {
              throw new MissingRequiredPropertyException("GetAssignedSubscriptionsAssignedSubscriptionCollectionItem", "regionAssignment");
            }
            this.regionAssignment = regionAssignment;
            return this;
        }
        @CustomType.Setter
        public Builder serviceName(String serviceName) {
            if (serviceName == null) {
              throw new MissingRequiredPropertyException("GetAssignedSubscriptionsAssignedSubscriptionCollectionItem", "serviceName");
            }
            this.serviceName = serviceName;
            return this;
        }
        @CustomType.Setter
        public Builder skuses(List<GetAssignedSubscriptionsAssignedSubscriptionCollectionItemSkus> skuses) {
            if (skuses == null) {
              throw new MissingRequiredPropertyException("GetAssignedSubscriptionsAssignedSubscriptionCollectionItem", "skuses");
            }
            this.skuses = skuses;
            return this;
        }
        public Builder skuses(GetAssignedSubscriptionsAssignedSubscriptionCollectionItemSkus... skuses) {
            return skuses(List.of(skuses));
        }
        @CustomType.Setter
        public Builder startDate(String startDate) {
            if (startDate == null) {
              throw new MissingRequiredPropertyException("GetAssignedSubscriptionsAssignedSubscriptionCollectionItem", "startDate");
            }
            this.startDate = startDate;
            return this;
        }
        @CustomType.Setter
        public Builder state(String state) {
            if (state == null) {
              throw new MissingRequiredPropertyException("GetAssignedSubscriptionsAssignedSubscriptionCollectionItem", "state");
            }
            this.state = state;
            return this;
        }
        @CustomType.Setter
        public Builder subscriptionNumber(String subscriptionNumber) {
            if (subscriptionNumber == null) {
              throw new MissingRequiredPropertyException("GetAssignedSubscriptionsAssignedSubscriptionCollectionItem", "subscriptionNumber");
            }
            this.subscriptionNumber = subscriptionNumber;
            return this;
        }
        @CustomType.Setter
        public Builder subscriptionTier(String subscriptionTier) {
            if (subscriptionTier == null) {
              throw new MissingRequiredPropertyException("GetAssignedSubscriptionsAssignedSubscriptionCollectionItem", "subscriptionTier");
            }
            this.subscriptionTier = subscriptionTier;
            return this;
        }
        @CustomType.Setter
        public Builder timeCreated(String timeCreated) {
            if (timeCreated == null) {
              throw new MissingRequiredPropertyException("GetAssignedSubscriptionsAssignedSubscriptionCollectionItem", "timeCreated");
            }
            this.timeCreated = timeCreated;
            return this;
        }
        @CustomType.Setter
        public Builder timeUpdated(String timeUpdated) {
            if (timeUpdated == null) {
              throw new MissingRequiredPropertyException("GetAssignedSubscriptionsAssignedSubscriptionCollectionItem", "timeUpdated");
            }
            this.timeUpdated = timeUpdated;
            return this;
        }
        public GetAssignedSubscriptionsAssignedSubscriptionCollectionItem build() {
            final var _resultValue = new GetAssignedSubscriptionsAssignedSubscriptionCollectionItem();
            _resultValue.classicSubscriptionId = classicSubscriptionId;
            _resultValue.cloudAmountCurrency = cloudAmountCurrency;
            _resultValue.compartmentId = compartmentId;
            _resultValue.csiNumber = csiNumber;
            _resultValue.currencyCode = currencyCode;
            _resultValue.customerCountryCode = customerCountryCode;
            _resultValue.definedTags = definedTags;
            _resultValue.endDate = endDate;
            _resultValue.entityVersion = entityVersion;
            _resultValue.freeformTags = freeformTags;
            _resultValue.id = id;
            _resultValue.isClassicSubscription = isClassicSubscription;
            _resultValue.isGovernmentSubscription = isGovernmentSubscription;
            _resultValue.managedBy = managedBy;
            _resultValue.orderIds = orderIds;
            _resultValue.programType = programType;
            _resultValue.promotions = promotions;
            _resultValue.purchaseEntitlementId = purchaseEntitlementId;
            _resultValue.regionAssignment = regionAssignment;
            _resultValue.serviceName = serviceName;
            _resultValue.skuses = skuses;
            _resultValue.startDate = startDate;
            _resultValue.state = state;
            _resultValue.subscriptionNumber = subscriptionNumber;
            _resultValue.subscriptionTier = subscriptionTier;
            _resultValue.timeCreated = timeCreated;
            _resultValue.timeUpdated = timeUpdated;
            return _resultValue;
        }
    }
}
