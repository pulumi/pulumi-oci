// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.OsubBillingSchedule.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.OsubBillingSchedule.outputs.GetBillingScheduleBillingScheduleProduct;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetBillingScheduleBillingSchedule {
    /**
     * @return Billing schedule line net amount
     * 
     */
    private String amount;
    /**
     * @return Indicates the associated AR Customer transaction id a unique identifier existing on AR.
     * 
     */
    private String arCustomerTransactionId;
    /**
     * @return Indicates the associated AR Invoice Number
     * 
     */
    private String arInvoiceNumber;
    /**
     * @return Billing frequency
     * 
     */
    private String billingFrequency;
    /**
     * @return Billing schedule invoice status
     * 
     */
    private String invoiceStatus;
    /**
     * @return Billing schedule net unit price
     * 
     */
    private String netUnitPrice;
    /**
     * @return Order number associated with the Subscribed Service
     * 
     */
    private String orderNumber;
    /**
     * @return Product description
     * 
     */
    private List<GetBillingScheduleBillingScheduleProduct> products;
    /**
     * @return Billing schedule quantity
     * 
     */
    private String quantity;
    /**
     * @return Billing schedule end date
     * 
     */
    private String timeEnd;
    /**
     * @return Billing schedule invoicing date
     * 
     */
    private String timeInvoicing;
    /**
     * @return Billing schedule start date
     * 
     */
    private String timeStart;

    private GetBillingScheduleBillingSchedule() {}
    /**
     * @return Billing schedule line net amount
     * 
     */
    public String amount() {
        return this.amount;
    }
    /**
     * @return Indicates the associated AR Customer transaction id a unique identifier existing on AR.
     * 
     */
    public String arCustomerTransactionId() {
        return this.arCustomerTransactionId;
    }
    /**
     * @return Indicates the associated AR Invoice Number
     * 
     */
    public String arInvoiceNumber() {
        return this.arInvoiceNumber;
    }
    /**
     * @return Billing frequency
     * 
     */
    public String billingFrequency() {
        return this.billingFrequency;
    }
    /**
     * @return Billing schedule invoice status
     * 
     */
    public String invoiceStatus() {
        return this.invoiceStatus;
    }
    /**
     * @return Billing schedule net unit price
     * 
     */
    public String netUnitPrice() {
        return this.netUnitPrice;
    }
    /**
     * @return Order number associated with the Subscribed Service
     * 
     */
    public String orderNumber() {
        return this.orderNumber;
    }
    /**
     * @return Product description
     * 
     */
    public List<GetBillingScheduleBillingScheduleProduct> products() {
        return this.products;
    }
    /**
     * @return Billing schedule quantity
     * 
     */
    public String quantity() {
        return this.quantity;
    }
    /**
     * @return Billing schedule end date
     * 
     */
    public String timeEnd() {
        return this.timeEnd;
    }
    /**
     * @return Billing schedule invoicing date
     * 
     */
    public String timeInvoicing() {
        return this.timeInvoicing;
    }
    /**
     * @return Billing schedule start date
     * 
     */
    public String timeStart() {
        return this.timeStart;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetBillingScheduleBillingSchedule defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String amount;
        private String arCustomerTransactionId;
        private String arInvoiceNumber;
        private String billingFrequency;
        private String invoiceStatus;
        private String netUnitPrice;
        private String orderNumber;
        private List<GetBillingScheduleBillingScheduleProduct> products;
        private String quantity;
        private String timeEnd;
        private String timeInvoicing;
        private String timeStart;
        public Builder() {}
        public Builder(GetBillingScheduleBillingSchedule defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.amount = defaults.amount;
    	      this.arCustomerTransactionId = defaults.arCustomerTransactionId;
    	      this.arInvoiceNumber = defaults.arInvoiceNumber;
    	      this.billingFrequency = defaults.billingFrequency;
    	      this.invoiceStatus = defaults.invoiceStatus;
    	      this.netUnitPrice = defaults.netUnitPrice;
    	      this.orderNumber = defaults.orderNumber;
    	      this.products = defaults.products;
    	      this.quantity = defaults.quantity;
    	      this.timeEnd = defaults.timeEnd;
    	      this.timeInvoicing = defaults.timeInvoicing;
    	      this.timeStart = defaults.timeStart;
        }

        @CustomType.Setter
        public Builder amount(String amount) {
            this.amount = Objects.requireNonNull(amount);
            return this;
        }
        @CustomType.Setter
        public Builder arCustomerTransactionId(String arCustomerTransactionId) {
            this.arCustomerTransactionId = Objects.requireNonNull(arCustomerTransactionId);
            return this;
        }
        @CustomType.Setter
        public Builder arInvoiceNumber(String arInvoiceNumber) {
            this.arInvoiceNumber = Objects.requireNonNull(arInvoiceNumber);
            return this;
        }
        @CustomType.Setter
        public Builder billingFrequency(String billingFrequency) {
            this.billingFrequency = Objects.requireNonNull(billingFrequency);
            return this;
        }
        @CustomType.Setter
        public Builder invoiceStatus(String invoiceStatus) {
            this.invoiceStatus = Objects.requireNonNull(invoiceStatus);
            return this;
        }
        @CustomType.Setter
        public Builder netUnitPrice(String netUnitPrice) {
            this.netUnitPrice = Objects.requireNonNull(netUnitPrice);
            return this;
        }
        @CustomType.Setter
        public Builder orderNumber(String orderNumber) {
            this.orderNumber = Objects.requireNonNull(orderNumber);
            return this;
        }
        @CustomType.Setter
        public Builder products(List<GetBillingScheduleBillingScheduleProduct> products) {
            this.products = Objects.requireNonNull(products);
            return this;
        }
        public Builder products(GetBillingScheduleBillingScheduleProduct... products) {
            return products(List.of(products));
        }
        @CustomType.Setter
        public Builder quantity(String quantity) {
            this.quantity = Objects.requireNonNull(quantity);
            return this;
        }
        @CustomType.Setter
        public Builder timeEnd(String timeEnd) {
            this.timeEnd = Objects.requireNonNull(timeEnd);
            return this;
        }
        @CustomType.Setter
        public Builder timeInvoicing(String timeInvoicing) {
            this.timeInvoicing = Objects.requireNonNull(timeInvoicing);
            return this;
        }
        @CustomType.Setter
        public Builder timeStart(String timeStart) {
            this.timeStart = Objects.requireNonNull(timeStart);
            return this;
        }
        public GetBillingScheduleBillingSchedule build() {
            final var o = new GetBillingScheduleBillingSchedule();
            o.amount = amount;
            o.arCustomerTransactionId = arCustomerTransactionId;
            o.arInvoiceNumber = arInvoiceNumber;
            o.billingFrequency = billingFrequency;
            o.invoiceStatus = invoiceStatus;
            o.netUnitPrice = netUnitPrice;
            o.orderNumber = orderNumber;
            o.products = products;
            o.quantity = quantity;
            o.timeEnd = timeEnd;
            o.timeInvoicing = timeInvoicing;
            o.timeStart = timeStart;
            return o;
        }
    }
}