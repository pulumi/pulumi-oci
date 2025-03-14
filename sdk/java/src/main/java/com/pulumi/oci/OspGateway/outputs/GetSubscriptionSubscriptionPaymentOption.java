// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.OspGateway.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetSubscriptionSubscriptionPaymentOption {
    /**
     * @return Credit card type.
     * 
     */
    private String creditCardType;
    /**
     * @return The email address of the paypal user.
     * 
     */
    private String emailAddress;
    /**
     * @return Agreement id for the paypal account.
     * 
     */
    private String extBillingAgreementId;
    /**
     * @return First name of the paypal user.
     * 
     */
    private String firstName;
    /**
     * @return Last four digits of the card.
     * 
     */
    private String lastDigits;
    /**
     * @return Last name of the paypal user.
     * 
     */
    private String lastName;
    /**
     * @return Name on the credit card.
     * 
     */
    private String nameOnCard;
    /**
     * @return Payment method
     * 
     */
    private String paymentMethod;
    /**
     * @return Expired date of the credit card.
     * 
     */
    private String timeExpiration;
    /**
     * @return Wallet instrument internal id.
     * 
     */
    private String walletInstrumentId;
    /**
     * @return Wallet transaction id.
     * 
     */
    private String walletTransactionId;

    private GetSubscriptionSubscriptionPaymentOption() {}
    /**
     * @return Credit card type.
     * 
     */
    public String creditCardType() {
        return this.creditCardType;
    }
    /**
     * @return The email address of the paypal user.
     * 
     */
    public String emailAddress() {
        return this.emailAddress;
    }
    /**
     * @return Agreement id for the paypal account.
     * 
     */
    public String extBillingAgreementId() {
        return this.extBillingAgreementId;
    }
    /**
     * @return First name of the paypal user.
     * 
     */
    public String firstName() {
        return this.firstName;
    }
    /**
     * @return Last four digits of the card.
     * 
     */
    public String lastDigits() {
        return this.lastDigits;
    }
    /**
     * @return Last name of the paypal user.
     * 
     */
    public String lastName() {
        return this.lastName;
    }
    /**
     * @return Name on the credit card.
     * 
     */
    public String nameOnCard() {
        return this.nameOnCard;
    }
    /**
     * @return Payment method
     * 
     */
    public String paymentMethod() {
        return this.paymentMethod;
    }
    /**
     * @return Expired date of the credit card.
     * 
     */
    public String timeExpiration() {
        return this.timeExpiration;
    }
    /**
     * @return Wallet instrument internal id.
     * 
     */
    public String walletInstrumentId() {
        return this.walletInstrumentId;
    }
    /**
     * @return Wallet transaction id.
     * 
     */
    public String walletTransactionId() {
        return this.walletTransactionId;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetSubscriptionSubscriptionPaymentOption defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String creditCardType;
        private String emailAddress;
        private String extBillingAgreementId;
        private String firstName;
        private String lastDigits;
        private String lastName;
        private String nameOnCard;
        private String paymentMethod;
        private String timeExpiration;
        private String walletInstrumentId;
        private String walletTransactionId;
        public Builder() {}
        public Builder(GetSubscriptionSubscriptionPaymentOption defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.creditCardType = defaults.creditCardType;
    	      this.emailAddress = defaults.emailAddress;
    	      this.extBillingAgreementId = defaults.extBillingAgreementId;
    	      this.firstName = defaults.firstName;
    	      this.lastDigits = defaults.lastDigits;
    	      this.lastName = defaults.lastName;
    	      this.nameOnCard = defaults.nameOnCard;
    	      this.paymentMethod = defaults.paymentMethod;
    	      this.timeExpiration = defaults.timeExpiration;
    	      this.walletInstrumentId = defaults.walletInstrumentId;
    	      this.walletTransactionId = defaults.walletTransactionId;
        }

        @CustomType.Setter
        public Builder creditCardType(String creditCardType) {
            if (creditCardType == null) {
              throw new MissingRequiredPropertyException("GetSubscriptionSubscriptionPaymentOption", "creditCardType");
            }
            this.creditCardType = creditCardType;
            return this;
        }
        @CustomType.Setter
        public Builder emailAddress(String emailAddress) {
            if (emailAddress == null) {
              throw new MissingRequiredPropertyException("GetSubscriptionSubscriptionPaymentOption", "emailAddress");
            }
            this.emailAddress = emailAddress;
            return this;
        }
        @CustomType.Setter
        public Builder extBillingAgreementId(String extBillingAgreementId) {
            if (extBillingAgreementId == null) {
              throw new MissingRequiredPropertyException("GetSubscriptionSubscriptionPaymentOption", "extBillingAgreementId");
            }
            this.extBillingAgreementId = extBillingAgreementId;
            return this;
        }
        @CustomType.Setter
        public Builder firstName(String firstName) {
            if (firstName == null) {
              throw new MissingRequiredPropertyException("GetSubscriptionSubscriptionPaymentOption", "firstName");
            }
            this.firstName = firstName;
            return this;
        }
        @CustomType.Setter
        public Builder lastDigits(String lastDigits) {
            if (lastDigits == null) {
              throw new MissingRequiredPropertyException("GetSubscriptionSubscriptionPaymentOption", "lastDigits");
            }
            this.lastDigits = lastDigits;
            return this;
        }
        @CustomType.Setter
        public Builder lastName(String lastName) {
            if (lastName == null) {
              throw new MissingRequiredPropertyException("GetSubscriptionSubscriptionPaymentOption", "lastName");
            }
            this.lastName = lastName;
            return this;
        }
        @CustomType.Setter
        public Builder nameOnCard(String nameOnCard) {
            if (nameOnCard == null) {
              throw new MissingRequiredPropertyException("GetSubscriptionSubscriptionPaymentOption", "nameOnCard");
            }
            this.nameOnCard = nameOnCard;
            return this;
        }
        @CustomType.Setter
        public Builder paymentMethod(String paymentMethod) {
            if (paymentMethod == null) {
              throw new MissingRequiredPropertyException("GetSubscriptionSubscriptionPaymentOption", "paymentMethod");
            }
            this.paymentMethod = paymentMethod;
            return this;
        }
        @CustomType.Setter
        public Builder timeExpiration(String timeExpiration) {
            if (timeExpiration == null) {
              throw new MissingRequiredPropertyException("GetSubscriptionSubscriptionPaymentOption", "timeExpiration");
            }
            this.timeExpiration = timeExpiration;
            return this;
        }
        @CustomType.Setter
        public Builder walletInstrumentId(String walletInstrumentId) {
            if (walletInstrumentId == null) {
              throw new MissingRequiredPropertyException("GetSubscriptionSubscriptionPaymentOption", "walletInstrumentId");
            }
            this.walletInstrumentId = walletInstrumentId;
            return this;
        }
        @CustomType.Setter
        public Builder walletTransactionId(String walletTransactionId) {
            if (walletTransactionId == null) {
              throw new MissingRequiredPropertyException("GetSubscriptionSubscriptionPaymentOption", "walletTransactionId");
            }
            this.walletTransactionId = walletTransactionId;
            return this;
        }
        public GetSubscriptionSubscriptionPaymentOption build() {
            final var _resultValue = new GetSubscriptionSubscriptionPaymentOption();
            _resultValue.creditCardType = creditCardType;
            _resultValue.emailAddress = emailAddress;
            _resultValue.extBillingAgreementId = extBillingAgreementId;
            _resultValue.firstName = firstName;
            _resultValue.lastDigits = lastDigits;
            _resultValue.lastName = lastName;
            _resultValue.nameOnCard = nameOnCard;
            _resultValue.paymentMethod = paymentMethod;
            _resultValue.timeExpiration = timeExpiration;
            _resultValue.walletInstrumentId = walletInstrumentId;
            _resultValue.walletTransactionId = walletTransactionId;
            return _resultValue;
        }
    }
}
