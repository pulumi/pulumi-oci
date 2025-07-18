// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.OspGateway.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.OspGateway.outputs.GetSubscriptionSubscriptionBillingAddress;
import com.pulumi.oci.OspGateway.outputs.GetSubscriptionSubscriptionPaymentGateway;
import com.pulumi.oci.OspGateway.outputs.GetSubscriptionSubscriptionPaymentOption;
import com.pulumi.oci.OspGateway.outputs.GetSubscriptionSubscriptionTaxInfo;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetSubscriptionSubscription {
    /**
     * @return Account type.
     * 
     */
    private String accountType;
    /**
     * @return Bill to customer Account id.
     * 
     */
    private String billToCustAccountId;
    /**
     * @return Address details model.
     * 
     */
    private List<GetSubscriptionSubscriptionBillingAddress> billingAddresses;
    /**
     * @return Currency code
     * 
     */
    private String currencyCode;
    /**
     * @return GSI Subscription external code.
     * 
     */
    private String gsiOrgCode;
    /**
     * @return Subscription id identifier (OCID).
     * 
     */
    private String id;
    /**
     * @return Corporate conversion allowed status
     * 
     */
    private Boolean isCorporateConversionAllowed;
    /**
     * @return Payment intension.
     * 
     */
    private Boolean isIntentToPay;
    /**
     * @return Language short code (en, de, hu, etc)
     * 
     */
    private String languageCode;
    /**
     * @return GSI organization external identifier.
     * 
     */
    private String organizationId;
    /**
     * @return Payment gateway details.
     * 
     */
    private List<GetSubscriptionSubscriptionPaymentGateway> paymentGateways;
    /**
     * @return Payment option list of a subscription.
     * 
     */
    private List<GetSubscriptionSubscriptionPaymentOption> paymentOptions;
    /**
     * @return Subscription plan type.
     * 
     */
    private String planType;
    /**
     * @return Ship to customer account role.
     * 
     */
    private String shipToCustAcctRoleId;
    /**
     * @return Ship to customer account site address id.
     * 
     */
    private String shipToCustAcctSiteId;
    /**
     * @return Subscription plan number.
     * 
     */
    private String subscriptionPlanNumber;
    /**
     * @return Tax details.
     * 
     */
    private List<GetSubscriptionSubscriptionTaxInfo> taxInfos;
    /**
     * @return Date of upgrade/conversion when account type changed from PERSONAL to CORPORATE
     * 
     */
    private String timePersonalToCorporateConv;
    /**
     * @return Date of upgrade/conversion when planType changed from FREE_TIER to PAYG
     * 
     */
    private String timePlanUpgrade;
    /**
     * @return Start date of the subscription.
     * 
     */
    private String timeStart;
    /**
     * @return Status of the upgrade.
     * 
     */
    private String upgradeState;
    /**
     * @return This field is used to describe the Upgrade State in case of error (E.g. Upgrade failure caused by interfacing Tax details- TaxError)
     * 
     */
    private String upgradeStateDetails;

    private GetSubscriptionSubscription() {}
    /**
     * @return Account type.
     * 
     */
    public String accountType() {
        return this.accountType;
    }
    /**
     * @return Bill to customer Account id.
     * 
     */
    public String billToCustAccountId() {
        return this.billToCustAccountId;
    }
    /**
     * @return Address details model.
     * 
     */
    public List<GetSubscriptionSubscriptionBillingAddress> billingAddresses() {
        return this.billingAddresses;
    }
    /**
     * @return Currency code
     * 
     */
    public String currencyCode() {
        return this.currencyCode;
    }
    /**
     * @return GSI Subscription external code.
     * 
     */
    public String gsiOrgCode() {
        return this.gsiOrgCode;
    }
    /**
     * @return Subscription id identifier (OCID).
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return Corporate conversion allowed status
     * 
     */
    public Boolean isCorporateConversionAllowed() {
        return this.isCorporateConversionAllowed;
    }
    /**
     * @return Payment intension.
     * 
     */
    public Boolean isIntentToPay() {
        return this.isIntentToPay;
    }
    /**
     * @return Language short code (en, de, hu, etc)
     * 
     */
    public String languageCode() {
        return this.languageCode;
    }
    /**
     * @return GSI organization external identifier.
     * 
     */
    public String organizationId() {
        return this.organizationId;
    }
    /**
     * @return Payment gateway details.
     * 
     */
    public List<GetSubscriptionSubscriptionPaymentGateway> paymentGateways() {
        return this.paymentGateways;
    }
    /**
     * @return Payment option list of a subscription.
     * 
     */
    public List<GetSubscriptionSubscriptionPaymentOption> paymentOptions() {
        return this.paymentOptions;
    }
    /**
     * @return Subscription plan type.
     * 
     */
    public String planType() {
        return this.planType;
    }
    /**
     * @return Ship to customer account role.
     * 
     */
    public String shipToCustAcctRoleId() {
        return this.shipToCustAcctRoleId;
    }
    /**
     * @return Ship to customer account site address id.
     * 
     */
    public String shipToCustAcctSiteId() {
        return this.shipToCustAcctSiteId;
    }
    /**
     * @return Subscription plan number.
     * 
     */
    public String subscriptionPlanNumber() {
        return this.subscriptionPlanNumber;
    }
    /**
     * @return Tax details.
     * 
     */
    public List<GetSubscriptionSubscriptionTaxInfo> taxInfos() {
        return this.taxInfos;
    }
    /**
     * @return Date of upgrade/conversion when account type changed from PERSONAL to CORPORATE
     * 
     */
    public String timePersonalToCorporateConv() {
        return this.timePersonalToCorporateConv;
    }
    /**
     * @return Date of upgrade/conversion when planType changed from FREE_TIER to PAYG
     * 
     */
    public String timePlanUpgrade() {
        return this.timePlanUpgrade;
    }
    /**
     * @return Start date of the subscription.
     * 
     */
    public String timeStart() {
        return this.timeStart;
    }
    /**
     * @return Status of the upgrade.
     * 
     */
    public String upgradeState() {
        return this.upgradeState;
    }
    /**
     * @return This field is used to describe the Upgrade State in case of error (E.g. Upgrade failure caused by interfacing Tax details- TaxError)
     * 
     */
    public String upgradeStateDetails() {
        return this.upgradeStateDetails;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetSubscriptionSubscription defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String accountType;
        private String billToCustAccountId;
        private List<GetSubscriptionSubscriptionBillingAddress> billingAddresses;
        private String currencyCode;
        private String gsiOrgCode;
        private String id;
        private Boolean isCorporateConversionAllowed;
        private Boolean isIntentToPay;
        private String languageCode;
        private String organizationId;
        private List<GetSubscriptionSubscriptionPaymentGateway> paymentGateways;
        private List<GetSubscriptionSubscriptionPaymentOption> paymentOptions;
        private String planType;
        private String shipToCustAcctRoleId;
        private String shipToCustAcctSiteId;
        private String subscriptionPlanNumber;
        private List<GetSubscriptionSubscriptionTaxInfo> taxInfos;
        private String timePersonalToCorporateConv;
        private String timePlanUpgrade;
        private String timeStart;
        private String upgradeState;
        private String upgradeStateDetails;
        public Builder() {}
        public Builder(GetSubscriptionSubscription defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.accountType = defaults.accountType;
    	      this.billToCustAccountId = defaults.billToCustAccountId;
    	      this.billingAddresses = defaults.billingAddresses;
    	      this.currencyCode = defaults.currencyCode;
    	      this.gsiOrgCode = defaults.gsiOrgCode;
    	      this.id = defaults.id;
    	      this.isCorporateConversionAllowed = defaults.isCorporateConversionAllowed;
    	      this.isIntentToPay = defaults.isIntentToPay;
    	      this.languageCode = defaults.languageCode;
    	      this.organizationId = defaults.organizationId;
    	      this.paymentGateways = defaults.paymentGateways;
    	      this.paymentOptions = defaults.paymentOptions;
    	      this.planType = defaults.planType;
    	      this.shipToCustAcctRoleId = defaults.shipToCustAcctRoleId;
    	      this.shipToCustAcctSiteId = defaults.shipToCustAcctSiteId;
    	      this.subscriptionPlanNumber = defaults.subscriptionPlanNumber;
    	      this.taxInfos = defaults.taxInfos;
    	      this.timePersonalToCorporateConv = defaults.timePersonalToCorporateConv;
    	      this.timePlanUpgrade = defaults.timePlanUpgrade;
    	      this.timeStart = defaults.timeStart;
    	      this.upgradeState = defaults.upgradeState;
    	      this.upgradeStateDetails = defaults.upgradeStateDetails;
        }

        @CustomType.Setter
        public Builder accountType(String accountType) {
            if (accountType == null) {
              throw new MissingRequiredPropertyException("GetSubscriptionSubscription", "accountType");
            }
            this.accountType = accountType;
            return this;
        }
        @CustomType.Setter
        public Builder billToCustAccountId(String billToCustAccountId) {
            if (billToCustAccountId == null) {
              throw new MissingRequiredPropertyException("GetSubscriptionSubscription", "billToCustAccountId");
            }
            this.billToCustAccountId = billToCustAccountId;
            return this;
        }
        @CustomType.Setter
        public Builder billingAddresses(List<GetSubscriptionSubscriptionBillingAddress> billingAddresses) {
            if (billingAddresses == null) {
              throw new MissingRequiredPropertyException("GetSubscriptionSubscription", "billingAddresses");
            }
            this.billingAddresses = billingAddresses;
            return this;
        }
        public Builder billingAddresses(GetSubscriptionSubscriptionBillingAddress... billingAddresses) {
            return billingAddresses(List.of(billingAddresses));
        }
        @CustomType.Setter
        public Builder currencyCode(String currencyCode) {
            if (currencyCode == null) {
              throw new MissingRequiredPropertyException("GetSubscriptionSubscription", "currencyCode");
            }
            this.currencyCode = currencyCode;
            return this;
        }
        @CustomType.Setter
        public Builder gsiOrgCode(String gsiOrgCode) {
            if (gsiOrgCode == null) {
              throw new MissingRequiredPropertyException("GetSubscriptionSubscription", "gsiOrgCode");
            }
            this.gsiOrgCode = gsiOrgCode;
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetSubscriptionSubscription", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder isCorporateConversionAllowed(Boolean isCorporateConversionAllowed) {
            if (isCorporateConversionAllowed == null) {
              throw new MissingRequiredPropertyException("GetSubscriptionSubscription", "isCorporateConversionAllowed");
            }
            this.isCorporateConversionAllowed = isCorporateConversionAllowed;
            return this;
        }
        @CustomType.Setter
        public Builder isIntentToPay(Boolean isIntentToPay) {
            if (isIntentToPay == null) {
              throw new MissingRequiredPropertyException("GetSubscriptionSubscription", "isIntentToPay");
            }
            this.isIntentToPay = isIntentToPay;
            return this;
        }
        @CustomType.Setter
        public Builder languageCode(String languageCode) {
            if (languageCode == null) {
              throw new MissingRequiredPropertyException("GetSubscriptionSubscription", "languageCode");
            }
            this.languageCode = languageCode;
            return this;
        }
        @CustomType.Setter
        public Builder organizationId(String organizationId) {
            if (organizationId == null) {
              throw new MissingRequiredPropertyException("GetSubscriptionSubscription", "organizationId");
            }
            this.organizationId = organizationId;
            return this;
        }
        @CustomType.Setter
        public Builder paymentGateways(List<GetSubscriptionSubscriptionPaymentGateway> paymentGateways) {
            if (paymentGateways == null) {
              throw new MissingRequiredPropertyException("GetSubscriptionSubscription", "paymentGateways");
            }
            this.paymentGateways = paymentGateways;
            return this;
        }
        public Builder paymentGateways(GetSubscriptionSubscriptionPaymentGateway... paymentGateways) {
            return paymentGateways(List.of(paymentGateways));
        }
        @CustomType.Setter
        public Builder paymentOptions(List<GetSubscriptionSubscriptionPaymentOption> paymentOptions) {
            if (paymentOptions == null) {
              throw new MissingRequiredPropertyException("GetSubscriptionSubscription", "paymentOptions");
            }
            this.paymentOptions = paymentOptions;
            return this;
        }
        public Builder paymentOptions(GetSubscriptionSubscriptionPaymentOption... paymentOptions) {
            return paymentOptions(List.of(paymentOptions));
        }
        @CustomType.Setter
        public Builder planType(String planType) {
            if (planType == null) {
              throw new MissingRequiredPropertyException("GetSubscriptionSubscription", "planType");
            }
            this.planType = planType;
            return this;
        }
        @CustomType.Setter
        public Builder shipToCustAcctRoleId(String shipToCustAcctRoleId) {
            if (shipToCustAcctRoleId == null) {
              throw new MissingRequiredPropertyException("GetSubscriptionSubscription", "shipToCustAcctRoleId");
            }
            this.shipToCustAcctRoleId = shipToCustAcctRoleId;
            return this;
        }
        @CustomType.Setter
        public Builder shipToCustAcctSiteId(String shipToCustAcctSiteId) {
            if (shipToCustAcctSiteId == null) {
              throw new MissingRequiredPropertyException("GetSubscriptionSubscription", "shipToCustAcctSiteId");
            }
            this.shipToCustAcctSiteId = shipToCustAcctSiteId;
            return this;
        }
        @CustomType.Setter
        public Builder subscriptionPlanNumber(String subscriptionPlanNumber) {
            if (subscriptionPlanNumber == null) {
              throw new MissingRequiredPropertyException("GetSubscriptionSubscription", "subscriptionPlanNumber");
            }
            this.subscriptionPlanNumber = subscriptionPlanNumber;
            return this;
        }
        @CustomType.Setter
        public Builder taxInfos(List<GetSubscriptionSubscriptionTaxInfo> taxInfos) {
            if (taxInfos == null) {
              throw new MissingRequiredPropertyException("GetSubscriptionSubscription", "taxInfos");
            }
            this.taxInfos = taxInfos;
            return this;
        }
        public Builder taxInfos(GetSubscriptionSubscriptionTaxInfo... taxInfos) {
            return taxInfos(List.of(taxInfos));
        }
        @CustomType.Setter
        public Builder timePersonalToCorporateConv(String timePersonalToCorporateConv) {
            if (timePersonalToCorporateConv == null) {
              throw new MissingRequiredPropertyException("GetSubscriptionSubscription", "timePersonalToCorporateConv");
            }
            this.timePersonalToCorporateConv = timePersonalToCorporateConv;
            return this;
        }
        @CustomType.Setter
        public Builder timePlanUpgrade(String timePlanUpgrade) {
            if (timePlanUpgrade == null) {
              throw new MissingRequiredPropertyException("GetSubscriptionSubscription", "timePlanUpgrade");
            }
            this.timePlanUpgrade = timePlanUpgrade;
            return this;
        }
        @CustomType.Setter
        public Builder timeStart(String timeStart) {
            if (timeStart == null) {
              throw new MissingRequiredPropertyException("GetSubscriptionSubscription", "timeStart");
            }
            this.timeStart = timeStart;
            return this;
        }
        @CustomType.Setter
        public Builder upgradeState(String upgradeState) {
            if (upgradeState == null) {
              throw new MissingRequiredPropertyException("GetSubscriptionSubscription", "upgradeState");
            }
            this.upgradeState = upgradeState;
            return this;
        }
        @CustomType.Setter
        public Builder upgradeStateDetails(String upgradeStateDetails) {
            if (upgradeStateDetails == null) {
              throw new MissingRequiredPropertyException("GetSubscriptionSubscription", "upgradeStateDetails");
            }
            this.upgradeStateDetails = upgradeStateDetails;
            return this;
        }
        public GetSubscriptionSubscription build() {
            final var _resultValue = new GetSubscriptionSubscription();
            _resultValue.accountType = accountType;
            _resultValue.billToCustAccountId = billToCustAccountId;
            _resultValue.billingAddresses = billingAddresses;
            _resultValue.currencyCode = currencyCode;
            _resultValue.gsiOrgCode = gsiOrgCode;
            _resultValue.id = id;
            _resultValue.isCorporateConversionAllowed = isCorporateConversionAllowed;
            _resultValue.isIntentToPay = isIntentToPay;
            _resultValue.languageCode = languageCode;
            _resultValue.organizationId = organizationId;
            _resultValue.paymentGateways = paymentGateways;
            _resultValue.paymentOptions = paymentOptions;
            _resultValue.planType = planType;
            _resultValue.shipToCustAcctRoleId = shipToCustAcctRoleId;
            _resultValue.shipToCustAcctSiteId = shipToCustAcctSiteId;
            _resultValue.subscriptionPlanNumber = subscriptionPlanNumber;
            _resultValue.taxInfos = taxInfos;
            _resultValue.timePersonalToCorporateConv = timePersonalToCorporateConv;
            _resultValue.timePlanUpgrade = timePlanUpgrade;
            _resultValue.timeStart = timeStart;
            _resultValue.upgradeState = upgradeState;
            _resultValue.upgradeStateDetails = upgradeStateDetails;
            return _resultValue;
        }
    }
}
