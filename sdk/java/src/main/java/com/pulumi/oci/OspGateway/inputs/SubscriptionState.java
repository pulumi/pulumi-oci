// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.OspGateway.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.OspGateway.inputs.SubscriptionBillingAddressArgs;
import com.pulumi.oci.OspGateway.inputs.SubscriptionPaymentGatewayArgs;
import com.pulumi.oci.OspGateway.inputs.SubscriptionPaymentOptionArgs;
import com.pulumi.oci.OspGateway.inputs.SubscriptionSubscriptionArgs;
import com.pulumi.oci.OspGateway.inputs.SubscriptionTaxInfoArgs;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class SubscriptionState extends com.pulumi.resources.ResourceArgs {

    public static final SubscriptionState Empty = new SubscriptionState();

    /**
     * (Updatable) Bill to customer Account id.
     * 
     */
    @Import(name="billToCustAccountId")
    private @Nullable Output<String> billToCustAccountId;

    /**
     * @return (Updatable) Bill to customer Account id.
     * 
     */
    public Optional<Output<String>> billToCustAccountId() {
        return Optional.ofNullable(this.billToCustAccountId);
    }

    /**
     * (Updatable) Billing address details model.
     * 
     */
    @Import(name="billingAddresses")
    private @Nullable Output<List<SubscriptionBillingAddressArgs>> billingAddresses;

    /**
     * @return (Updatable) Billing address details model.
     * 
     */
    public Optional<Output<List<SubscriptionBillingAddressArgs>>> billingAddresses() {
        return Optional.ofNullable(this.billingAddresses);
    }

    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    @Import(name="compartmentId")
    private @Nullable Output<String> compartmentId;

    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    public Optional<Output<String>> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
    }

    /**
     * (Updatable) Currency code
     * 
     */
    @Import(name="currencyCode")
    private @Nullable Output<String> currencyCode;

    /**
     * @return (Updatable) Currency code
     * 
     */
    public Optional<Output<String>> currencyCode() {
        return Optional.ofNullable(this.currencyCode);
    }

    /**
     * (Updatable) User email
     * 
     */
    @Import(name="email")
    private @Nullable Output<String> email;

    /**
     * @return (Updatable) User email
     * 
     */
    public Optional<Output<String>> email() {
        return Optional.ofNullable(this.email);
    }

    /**
     * (Updatable) GSI Subscription external code.
     * 
     */
    @Import(name="gsiOrgCode")
    private @Nullable Output<String> gsiOrgCode;

    /**
     * @return (Updatable) GSI Subscription external code.
     * 
     */
    public Optional<Output<String>> gsiOrgCode() {
        return Optional.ofNullable(this.gsiOrgCode);
    }

    /**
     * (Updatable) Payment intension.
     * 
     */
    @Import(name="isIntentToPay")
    private @Nullable Output<Boolean> isIntentToPay;

    /**
     * @return (Updatable) Payment intension.
     * 
     */
    public Optional<Output<Boolean>> isIntentToPay() {
        return Optional.ofNullable(this.isIntentToPay);
    }

    /**
     * (Updatable) Language short code (en, de, hu, etc)
     * 
     */
    @Import(name="languageCode")
    private @Nullable Output<String> languageCode;

    /**
     * @return (Updatable) Language short code (en, de, hu, etc)
     * 
     */
    public Optional<Output<String>> languageCode() {
        return Optional.ofNullable(this.languageCode);
    }

    /**
     * (Updatable) GSI organization external identifier.
     * 
     */
    @Import(name="organizationId")
    private @Nullable Output<String> organizationId;

    /**
     * @return (Updatable) GSI organization external identifier.
     * 
     */
    public Optional<Output<String>> organizationId() {
        return Optional.ofNullable(this.organizationId);
    }

    /**
     * (Updatable) The home region&#39;s public name of the logged in user.
     * 
     */
    @Import(name="ospHomeRegion")
    private @Nullable Output<String> ospHomeRegion;

    /**
     * @return (Updatable) The home region&#39;s public name of the logged in user.
     * 
     */
    public Optional<Output<String>> ospHomeRegion() {
        return Optional.ofNullable(this.ospHomeRegion);
    }

    /**
     * (Updatable) Payment gateway details.
     * 
     */
    @Import(name="paymentGateways")
    private @Nullable Output<List<SubscriptionPaymentGatewayArgs>> paymentGateways;

    /**
     * @return (Updatable) Payment gateway details.
     * 
     */
    public Optional<Output<List<SubscriptionPaymentGatewayArgs>>> paymentGateways() {
        return Optional.ofNullable(this.paymentGateways);
    }

    /**
     * (Updatable) Payment option list of a subscription.
     * 
     */
    @Import(name="paymentOptions")
    private @Nullable Output<List<SubscriptionPaymentOptionArgs>> paymentOptions;

    /**
     * @return (Updatable) Payment option list of a subscription.
     * 
     */
    public Optional<Output<List<SubscriptionPaymentOptionArgs>>> paymentOptions() {
        return Optional.ofNullable(this.paymentOptions);
    }

    /**
     * (Updatable) Subscription plan type.
     * 
     */
    @Import(name="planType")
    private @Nullable Output<String> planType;

    /**
     * @return (Updatable) Subscription plan type.
     * 
     */
    public Optional<Output<String>> planType() {
        return Optional.ofNullable(this.planType);
    }

    /**
     * (Updatable) Ship to customer account role.
     * 
     */
    @Import(name="shipToCustAcctRoleId")
    private @Nullable Output<String> shipToCustAcctRoleId;

    /**
     * @return (Updatable) Ship to customer account role.
     * 
     */
    public Optional<Output<String>> shipToCustAcctRoleId() {
        return Optional.ofNullable(this.shipToCustAcctRoleId);
    }

    /**
     * (Updatable) Ship to customer account site address id.
     * 
     */
    @Import(name="shipToCustAcctSiteId")
    private @Nullable Output<String> shipToCustAcctSiteId;

    /**
     * @return (Updatable) Ship to customer account site address id.
     * 
     */
    public Optional<Output<String>> shipToCustAcctSiteId() {
        return Optional.ofNullable(this.shipToCustAcctSiteId);
    }

    /**
     * (Updatable) Subscription details object which extends the SubscriptionSummary
     * 
     */
    @Import(name="subscription")
    private @Nullable Output<SubscriptionSubscriptionArgs> subscription;

    /**
     * @return (Updatable) Subscription details object which extends the SubscriptionSummary
     * 
     */
    public Optional<Output<SubscriptionSubscriptionArgs>> subscription() {
        return Optional.ofNullable(this.subscription);
    }

    /**
     * Subscription id(OCID).
     * 
     */
    @Import(name="subscriptionId")
    private @Nullable Output<String> subscriptionId;

    /**
     * @return Subscription id(OCID).
     * 
     */
    public Optional<Output<String>> subscriptionId() {
        return Optional.ofNullable(this.subscriptionId);
    }

    /**
     * (Updatable) Subscription plan number.
     * 
     */
    @Import(name="subscriptionPlanNumber")
    private @Nullable Output<String> subscriptionPlanNumber;

    /**
     * @return (Updatable) Subscription plan number.
     * 
     */
    public Optional<Output<String>> subscriptionPlanNumber() {
        return Optional.ofNullable(this.subscriptionPlanNumber);
    }

    /**
     * (Updatable) Tax details.
     * 
     */
    @Import(name="taxInfos")
    private @Nullable Output<List<SubscriptionTaxInfoArgs>> taxInfos;

    /**
     * @return (Updatable) Tax details.
     * 
     */
    public Optional<Output<List<SubscriptionTaxInfoArgs>>> taxInfos() {
        return Optional.ofNullable(this.taxInfos);
    }

    /**
     * (Updatable) Date of upgrade/conversion when planType changed from FREE_TIER to PAYG
     * 
     */
    @Import(name="timePlanUpgrade")
    private @Nullable Output<String> timePlanUpgrade;

    /**
     * @return (Updatable) Date of upgrade/conversion when planType changed from FREE_TIER to PAYG
     * 
     */
    public Optional<Output<String>> timePlanUpgrade() {
        return Optional.ofNullable(this.timePlanUpgrade);
    }

    /**
     * (Updatable) Start date of the subscription.
     * 
     */
    @Import(name="timeStart")
    private @Nullable Output<String> timeStart;

    /**
     * @return (Updatable) Start date of the subscription.
     * 
     */
    public Optional<Output<String>> timeStart() {
        return Optional.ofNullable(this.timeStart);
    }

    /**
     * (Updatable) Status of the upgrade.
     * 
     */
    @Import(name="upgradeState")
    private @Nullable Output<String> upgradeState;

    /**
     * @return (Updatable) Status of the upgrade.
     * 
     */
    public Optional<Output<String>> upgradeState() {
        return Optional.ofNullable(this.upgradeState);
    }

    /**
     * (Updatable) This field is used to describe the Upgrade State in case of error (E.g. Upgrade failure caused by interfacing Tax details- TaxError)
     * 
     */
    @Import(name="upgradeStateDetails")
    private @Nullable Output<String> upgradeStateDetails;

    /**
     * @return (Updatable) This field is used to describe the Upgrade State in case of error (E.g. Upgrade failure caused by interfacing Tax details- TaxError)
     * 
     */
    public Optional<Output<String>> upgradeStateDetails() {
        return Optional.ofNullable(this.upgradeStateDetails);
    }

    private SubscriptionState() {}

    private SubscriptionState(SubscriptionState $) {
        this.billToCustAccountId = $.billToCustAccountId;
        this.billingAddresses = $.billingAddresses;
        this.compartmentId = $.compartmentId;
        this.currencyCode = $.currencyCode;
        this.email = $.email;
        this.gsiOrgCode = $.gsiOrgCode;
        this.isIntentToPay = $.isIntentToPay;
        this.languageCode = $.languageCode;
        this.organizationId = $.organizationId;
        this.ospHomeRegion = $.ospHomeRegion;
        this.paymentGateways = $.paymentGateways;
        this.paymentOptions = $.paymentOptions;
        this.planType = $.planType;
        this.shipToCustAcctRoleId = $.shipToCustAcctRoleId;
        this.shipToCustAcctSiteId = $.shipToCustAcctSiteId;
        this.subscription = $.subscription;
        this.subscriptionId = $.subscriptionId;
        this.subscriptionPlanNumber = $.subscriptionPlanNumber;
        this.taxInfos = $.taxInfos;
        this.timePlanUpgrade = $.timePlanUpgrade;
        this.timeStart = $.timeStart;
        this.upgradeState = $.upgradeState;
        this.upgradeStateDetails = $.upgradeStateDetails;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(SubscriptionState defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private SubscriptionState $;

        public Builder() {
            $ = new SubscriptionState();
        }

        public Builder(SubscriptionState defaults) {
            $ = new SubscriptionState(Objects.requireNonNull(defaults));
        }

        /**
         * @param billToCustAccountId (Updatable) Bill to customer Account id.
         * 
         * @return builder
         * 
         */
        public Builder billToCustAccountId(@Nullable Output<String> billToCustAccountId) {
            $.billToCustAccountId = billToCustAccountId;
            return this;
        }

        /**
         * @param billToCustAccountId (Updatable) Bill to customer Account id.
         * 
         * @return builder
         * 
         */
        public Builder billToCustAccountId(String billToCustAccountId) {
            return billToCustAccountId(Output.of(billToCustAccountId));
        }

        /**
         * @param billingAddresses (Updatable) Billing address details model.
         * 
         * @return builder
         * 
         */
        public Builder billingAddresses(@Nullable Output<List<SubscriptionBillingAddressArgs>> billingAddresses) {
            $.billingAddresses = billingAddresses;
            return this;
        }

        /**
         * @param billingAddresses (Updatable) Billing address details model.
         * 
         * @return builder
         * 
         */
        public Builder billingAddresses(List<SubscriptionBillingAddressArgs> billingAddresses) {
            return billingAddresses(Output.of(billingAddresses));
        }

        /**
         * @param billingAddresses (Updatable) Billing address details model.
         * 
         * @return builder
         * 
         */
        public Builder billingAddresses(SubscriptionBillingAddressArgs... billingAddresses) {
            return billingAddresses(List.of(billingAddresses));
        }

        /**
         * @param compartmentId (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(@Nullable Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param currencyCode (Updatable) Currency code
         * 
         * @return builder
         * 
         */
        public Builder currencyCode(@Nullable Output<String> currencyCode) {
            $.currencyCode = currencyCode;
            return this;
        }

        /**
         * @param currencyCode (Updatable) Currency code
         * 
         * @return builder
         * 
         */
        public Builder currencyCode(String currencyCode) {
            return currencyCode(Output.of(currencyCode));
        }

        /**
         * @param email (Updatable) User email
         * 
         * @return builder
         * 
         */
        public Builder email(@Nullable Output<String> email) {
            $.email = email;
            return this;
        }

        /**
         * @param email (Updatable) User email
         * 
         * @return builder
         * 
         */
        public Builder email(String email) {
            return email(Output.of(email));
        }

        /**
         * @param gsiOrgCode (Updatable) GSI Subscription external code.
         * 
         * @return builder
         * 
         */
        public Builder gsiOrgCode(@Nullable Output<String> gsiOrgCode) {
            $.gsiOrgCode = gsiOrgCode;
            return this;
        }

        /**
         * @param gsiOrgCode (Updatable) GSI Subscription external code.
         * 
         * @return builder
         * 
         */
        public Builder gsiOrgCode(String gsiOrgCode) {
            return gsiOrgCode(Output.of(gsiOrgCode));
        }

        /**
         * @param isIntentToPay (Updatable) Payment intension.
         * 
         * @return builder
         * 
         */
        public Builder isIntentToPay(@Nullable Output<Boolean> isIntentToPay) {
            $.isIntentToPay = isIntentToPay;
            return this;
        }

        /**
         * @param isIntentToPay (Updatable) Payment intension.
         * 
         * @return builder
         * 
         */
        public Builder isIntentToPay(Boolean isIntentToPay) {
            return isIntentToPay(Output.of(isIntentToPay));
        }

        /**
         * @param languageCode (Updatable) Language short code (en, de, hu, etc)
         * 
         * @return builder
         * 
         */
        public Builder languageCode(@Nullable Output<String> languageCode) {
            $.languageCode = languageCode;
            return this;
        }

        /**
         * @param languageCode (Updatable) Language short code (en, de, hu, etc)
         * 
         * @return builder
         * 
         */
        public Builder languageCode(String languageCode) {
            return languageCode(Output.of(languageCode));
        }

        /**
         * @param organizationId (Updatable) GSI organization external identifier.
         * 
         * @return builder
         * 
         */
        public Builder organizationId(@Nullable Output<String> organizationId) {
            $.organizationId = organizationId;
            return this;
        }

        /**
         * @param organizationId (Updatable) GSI organization external identifier.
         * 
         * @return builder
         * 
         */
        public Builder organizationId(String organizationId) {
            return organizationId(Output.of(organizationId));
        }

        /**
         * @param ospHomeRegion (Updatable) The home region&#39;s public name of the logged in user.
         * 
         * @return builder
         * 
         */
        public Builder ospHomeRegion(@Nullable Output<String> ospHomeRegion) {
            $.ospHomeRegion = ospHomeRegion;
            return this;
        }

        /**
         * @param ospHomeRegion (Updatable) The home region&#39;s public name of the logged in user.
         * 
         * @return builder
         * 
         */
        public Builder ospHomeRegion(String ospHomeRegion) {
            return ospHomeRegion(Output.of(ospHomeRegion));
        }

        /**
         * @param paymentGateways (Updatable) Payment gateway details.
         * 
         * @return builder
         * 
         */
        public Builder paymentGateways(@Nullable Output<List<SubscriptionPaymentGatewayArgs>> paymentGateways) {
            $.paymentGateways = paymentGateways;
            return this;
        }

        /**
         * @param paymentGateways (Updatable) Payment gateway details.
         * 
         * @return builder
         * 
         */
        public Builder paymentGateways(List<SubscriptionPaymentGatewayArgs> paymentGateways) {
            return paymentGateways(Output.of(paymentGateways));
        }

        /**
         * @param paymentGateways (Updatable) Payment gateway details.
         * 
         * @return builder
         * 
         */
        public Builder paymentGateways(SubscriptionPaymentGatewayArgs... paymentGateways) {
            return paymentGateways(List.of(paymentGateways));
        }

        /**
         * @param paymentOptions (Updatable) Payment option list of a subscription.
         * 
         * @return builder
         * 
         */
        public Builder paymentOptions(@Nullable Output<List<SubscriptionPaymentOptionArgs>> paymentOptions) {
            $.paymentOptions = paymentOptions;
            return this;
        }

        /**
         * @param paymentOptions (Updatable) Payment option list of a subscription.
         * 
         * @return builder
         * 
         */
        public Builder paymentOptions(List<SubscriptionPaymentOptionArgs> paymentOptions) {
            return paymentOptions(Output.of(paymentOptions));
        }

        /**
         * @param paymentOptions (Updatable) Payment option list of a subscription.
         * 
         * @return builder
         * 
         */
        public Builder paymentOptions(SubscriptionPaymentOptionArgs... paymentOptions) {
            return paymentOptions(List.of(paymentOptions));
        }

        /**
         * @param planType (Updatable) Subscription plan type.
         * 
         * @return builder
         * 
         */
        public Builder planType(@Nullable Output<String> planType) {
            $.planType = planType;
            return this;
        }

        /**
         * @param planType (Updatable) Subscription plan type.
         * 
         * @return builder
         * 
         */
        public Builder planType(String planType) {
            return planType(Output.of(planType));
        }

        /**
         * @param shipToCustAcctRoleId (Updatable) Ship to customer account role.
         * 
         * @return builder
         * 
         */
        public Builder shipToCustAcctRoleId(@Nullable Output<String> shipToCustAcctRoleId) {
            $.shipToCustAcctRoleId = shipToCustAcctRoleId;
            return this;
        }

        /**
         * @param shipToCustAcctRoleId (Updatable) Ship to customer account role.
         * 
         * @return builder
         * 
         */
        public Builder shipToCustAcctRoleId(String shipToCustAcctRoleId) {
            return shipToCustAcctRoleId(Output.of(shipToCustAcctRoleId));
        }

        /**
         * @param shipToCustAcctSiteId (Updatable) Ship to customer account site address id.
         * 
         * @return builder
         * 
         */
        public Builder shipToCustAcctSiteId(@Nullable Output<String> shipToCustAcctSiteId) {
            $.shipToCustAcctSiteId = shipToCustAcctSiteId;
            return this;
        }

        /**
         * @param shipToCustAcctSiteId (Updatable) Ship to customer account site address id.
         * 
         * @return builder
         * 
         */
        public Builder shipToCustAcctSiteId(String shipToCustAcctSiteId) {
            return shipToCustAcctSiteId(Output.of(shipToCustAcctSiteId));
        }

        /**
         * @param subscription (Updatable) Subscription details object which extends the SubscriptionSummary
         * 
         * @return builder
         * 
         */
        public Builder subscription(@Nullable Output<SubscriptionSubscriptionArgs> subscription) {
            $.subscription = subscription;
            return this;
        }

        /**
         * @param subscription (Updatable) Subscription details object which extends the SubscriptionSummary
         * 
         * @return builder
         * 
         */
        public Builder subscription(SubscriptionSubscriptionArgs subscription) {
            return subscription(Output.of(subscription));
        }

        /**
         * @param subscriptionId Subscription id(OCID).
         * 
         * @return builder
         * 
         */
        public Builder subscriptionId(@Nullable Output<String> subscriptionId) {
            $.subscriptionId = subscriptionId;
            return this;
        }

        /**
         * @param subscriptionId Subscription id(OCID).
         * 
         * @return builder
         * 
         */
        public Builder subscriptionId(String subscriptionId) {
            return subscriptionId(Output.of(subscriptionId));
        }

        /**
         * @param subscriptionPlanNumber (Updatable) Subscription plan number.
         * 
         * @return builder
         * 
         */
        public Builder subscriptionPlanNumber(@Nullable Output<String> subscriptionPlanNumber) {
            $.subscriptionPlanNumber = subscriptionPlanNumber;
            return this;
        }

        /**
         * @param subscriptionPlanNumber (Updatable) Subscription plan number.
         * 
         * @return builder
         * 
         */
        public Builder subscriptionPlanNumber(String subscriptionPlanNumber) {
            return subscriptionPlanNumber(Output.of(subscriptionPlanNumber));
        }

        /**
         * @param taxInfos (Updatable) Tax details.
         * 
         * @return builder
         * 
         */
        public Builder taxInfos(@Nullable Output<List<SubscriptionTaxInfoArgs>> taxInfos) {
            $.taxInfos = taxInfos;
            return this;
        }

        /**
         * @param taxInfos (Updatable) Tax details.
         * 
         * @return builder
         * 
         */
        public Builder taxInfos(List<SubscriptionTaxInfoArgs> taxInfos) {
            return taxInfos(Output.of(taxInfos));
        }

        /**
         * @param taxInfos (Updatable) Tax details.
         * 
         * @return builder
         * 
         */
        public Builder taxInfos(SubscriptionTaxInfoArgs... taxInfos) {
            return taxInfos(List.of(taxInfos));
        }

        /**
         * @param timePlanUpgrade (Updatable) Date of upgrade/conversion when planType changed from FREE_TIER to PAYG
         * 
         * @return builder
         * 
         */
        public Builder timePlanUpgrade(@Nullable Output<String> timePlanUpgrade) {
            $.timePlanUpgrade = timePlanUpgrade;
            return this;
        }

        /**
         * @param timePlanUpgrade (Updatable) Date of upgrade/conversion when planType changed from FREE_TIER to PAYG
         * 
         * @return builder
         * 
         */
        public Builder timePlanUpgrade(String timePlanUpgrade) {
            return timePlanUpgrade(Output.of(timePlanUpgrade));
        }

        /**
         * @param timeStart (Updatable) Start date of the subscription.
         * 
         * @return builder
         * 
         */
        public Builder timeStart(@Nullable Output<String> timeStart) {
            $.timeStart = timeStart;
            return this;
        }

        /**
         * @param timeStart (Updatable) Start date of the subscription.
         * 
         * @return builder
         * 
         */
        public Builder timeStart(String timeStart) {
            return timeStart(Output.of(timeStart));
        }

        /**
         * @param upgradeState (Updatable) Status of the upgrade.
         * 
         * @return builder
         * 
         */
        public Builder upgradeState(@Nullable Output<String> upgradeState) {
            $.upgradeState = upgradeState;
            return this;
        }

        /**
         * @param upgradeState (Updatable) Status of the upgrade.
         * 
         * @return builder
         * 
         */
        public Builder upgradeState(String upgradeState) {
            return upgradeState(Output.of(upgradeState));
        }

        /**
         * @param upgradeStateDetails (Updatable) This field is used to describe the Upgrade State in case of error (E.g. Upgrade failure caused by interfacing Tax details- TaxError)
         * 
         * @return builder
         * 
         */
        public Builder upgradeStateDetails(@Nullable Output<String> upgradeStateDetails) {
            $.upgradeStateDetails = upgradeStateDetails;
            return this;
        }

        /**
         * @param upgradeStateDetails (Updatable) This field is used to describe the Upgrade State in case of error (E.g. Upgrade failure caused by interfacing Tax details- TaxError)
         * 
         * @return builder
         * 
         */
        public Builder upgradeStateDetails(String upgradeStateDetails) {
            return upgradeStateDetails(Output.of(upgradeStateDetails));
        }

        public SubscriptionState build() {
            return $;
        }
    }

}