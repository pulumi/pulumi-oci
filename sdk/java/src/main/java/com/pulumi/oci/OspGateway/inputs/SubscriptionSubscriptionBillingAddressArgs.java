// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.OspGateway.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class SubscriptionSubscriptionBillingAddressArgs extends com.pulumi.resources.ResourceArgs {

    public static final SubscriptionSubscriptionBillingAddressArgs Empty = new SubscriptionSubscriptionBillingAddressArgs();

    /**
     * (Updatable) Address identifier.
     * 
     */
    @Import(name="addressKey")
    private @Nullable Output<String> addressKey;

    /**
     * @return (Updatable) Address identifier.
     * 
     */
    public Optional<Output<String>> addressKey() {
        return Optional.ofNullable(this.addressKey);
    }

    /**
     * (Updatable) Name of the city.
     * 
     */
    @Import(name="city")
    private @Nullable Output<String> city;

    /**
     * @return (Updatable) Name of the city.
     * 
     */
    public Optional<Output<String>> city() {
        return Optional.ofNullable(this.city);
    }

    /**
     * (Updatable) Name of the customer company.
     * 
     */
    @Import(name="companyName")
    private @Nullable Output<String> companyName;

    /**
     * @return (Updatable) Name of the customer company.
     * 
     */
    public Optional<Output<String>> companyName() {
        return Optional.ofNullable(this.companyName);
    }

    /**
     * (Updatable) Country of the address.
     * 
     */
    @Import(name="country")
    private @Nullable Output<String> country;

    /**
     * @return (Updatable) Country of the address.
     * 
     */
    public Optional<Output<String>> country() {
        return Optional.ofNullable(this.country);
    }

    /**
     * (Updatable) The email address of the paypal user.
     * 
     */
    @Import(name="emailAddress")
    private @Nullable Output<String> emailAddress;

    /**
     * @return (Updatable) The email address of the paypal user.
     * 
     */
    public Optional<Output<String>> emailAddress() {
        return Optional.ofNullable(this.emailAddress);
    }

    /**
     * (Updatable) First name of the paypal user.
     * 
     */
    @Import(name="firstName")
    private @Nullable Output<String> firstName;

    /**
     * @return (Updatable) First name of the paypal user.
     * 
     */
    public Optional<Output<String>> firstName() {
        return Optional.ofNullable(this.firstName);
    }

    /**
     * (Updatable) Last name of the paypal user.
     * 
     */
    @Import(name="lastName")
    private @Nullable Output<String> lastName;

    /**
     * @return (Updatable) Last name of the paypal user.
     * 
     */
    public Optional<Output<String>> lastName() {
        return Optional.ofNullable(this.lastName);
    }

    /**
     * (Updatable) Address line 1.
     * 
     */
    @Import(name="line1")
    private @Nullable Output<String> line1;

    /**
     * @return (Updatable) Address line 1.
     * 
     */
    public Optional<Output<String>> line1() {
        return Optional.ofNullable(this.line1);
    }

    /**
     * (Updatable) Address line 2.
     * 
     */
    @Import(name="line2")
    private @Nullable Output<String> line2;

    /**
     * @return (Updatable) Address line 2.
     * 
     */
    public Optional<Output<String>> line2() {
        return Optional.ofNullable(this.line2);
    }

    /**
     * (Updatable) Post code of the address.
     * 
     */
    @Import(name="postalCode")
    private @Nullable Output<String> postalCode;

    /**
     * @return (Updatable) Post code of the address.
     * 
     */
    public Optional<Output<String>> postalCode() {
        return Optional.ofNullable(this.postalCode);
    }

    /**
     * (Updatable) State of the address.
     * 
     */
    @Import(name="state")
    private @Nullable Output<String> state;

    /**
     * @return (Updatable) State of the address.
     * 
     */
    public Optional<Output<String>> state() {
        return Optional.ofNullable(this.state);
    }

    private SubscriptionSubscriptionBillingAddressArgs() {}

    private SubscriptionSubscriptionBillingAddressArgs(SubscriptionSubscriptionBillingAddressArgs $) {
        this.addressKey = $.addressKey;
        this.city = $.city;
        this.companyName = $.companyName;
        this.country = $.country;
        this.emailAddress = $.emailAddress;
        this.firstName = $.firstName;
        this.lastName = $.lastName;
        this.line1 = $.line1;
        this.line2 = $.line2;
        this.postalCode = $.postalCode;
        this.state = $.state;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(SubscriptionSubscriptionBillingAddressArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private SubscriptionSubscriptionBillingAddressArgs $;

        public Builder() {
            $ = new SubscriptionSubscriptionBillingAddressArgs();
        }

        public Builder(SubscriptionSubscriptionBillingAddressArgs defaults) {
            $ = new SubscriptionSubscriptionBillingAddressArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param addressKey (Updatable) Address identifier.
         * 
         * @return builder
         * 
         */
        public Builder addressKey(@Nullable Output<String> addressKey) {
            $.addressKey = addressKey;
            return this;
        }

        /**
         * @param addressKey (Updatable) Address identifier.
         * 
         * @return builder
         * 
         */
        public Builder addressKey(String addressKey) {
            return addressKey(Output.of(addressKey));
        }

        /**
         * @param city (Updatable) Name of the city.
         * 
         * @return builder
         * 
         */
        public Builder city(@Nullable Output<String> city) {
            $.city = city;
            return this;
        }

        /**
         * @param city (Updatable) Name of the city.
         * 
         * @return builder
         * 
         */
        public Builder city(String city) {
            return city(Output.of(city));
        }

        /**
         * @param companyName (Updatable) Name of the customer company.
         * 
         * @return builder
         * 
         */
        public Builder companyName(@Nullable Output<String> companyName) {
            $.companyName = companyName;
            return this;
        }

        /**
         * @param companyName (Updatable) Name of the customer company.
         * 
         * @return builder
         * 
         */
        public Builder companyName(String companyName) {
            return companyName(Output.of(companyName));
        }

        /**
         * @param country (Updatable) Country of the address.
         * 
         * @return builder
         * 
         */
        public Builder country(@Nullable Output<String> country) {
            $.country = country;
            return this;
        }

        /**
         * @param country (Updatable) Country of the address.
         * 
         * @return builder
         * 
         */
        public Builder country(String country) {
            return country(Output.of(country));
        }

        /**
         * @param emailAddress (Updatable) The email address of the paypal user.
         * 
         * @return builder
         * 
         */
        public Builder emailAddress(@Nullable Output<String> emailAddress) {
            $.emailAddress = emailAddress;
            return this;
        }

        /**
         * @param emailAddress (Updatable) The email address of the paypal user.
         * 
         * @return builder
         * 
         */
        public Builder emailAddress(String emailAddress) {
            return emailAddress(Output.of(emailAddress));
        }

        /**
         * @param firstName (Updatable) First name of the paypal user.
         * 
         * @return builder
         * 
         */
        public Builder firstName(@Nullable Output<String> firstName) {
            $.firstName = firstName;
            return this;
        }

        /**
         * @param firstName (Updatable) First name of the paypal user.
         * 
         * @return builder
         * 
         */
        public Builder firstName(String firstName) {
            return firstName(Output.of(firstName));
        }

        /**
         * @param lastName (Updatable) Last name of the paypal user.
         * 
         * @return builder
         * 
         */
        public Builder lastName(@Nullable Output<String> lastName) {
            $.lastName = lastName;
            return this;
        }

        /**
         * @param lastName (Updatable) Last name of the paypal user.
         * 
         * @return builder
         * 
         */
        public Builder lastName(String lastName) {
            return lastName(Output.of(lastName));
        }

        /**
         * @param line1 (Updatable) Address line 1.
         * 
         * @return builder
         * 
         */
        public Builder line1(@Nullable Output<String> line1) {
            $.line1 = line1;
            return this;
        }

        /**
         * @param line1 (Updatable) Address line 1.
         * 
         * @return builder
         * 
         */
        public Builder line1(String line1) {
            return line1(Output.of(line1));
        }

        /**
         * @param line2 (Updatable) Address line 2.
         * 
         * @return builder
         * 
         */
        public Builder line2(@Nullable Output<String> line2) {
            $.line2 = line2;
            return this;
        }

        /**
         * @param line2 (Updatable) Address line 2.
         * 
         * @return builder
         * 
         */
        public Builder line2(String line2) {
            return line2(Output.of(line2));
        }

        /**
         * @param postalCode (Updatable) Post code of the address.
         * 
         * @return builder
         * 
         */
        public Builder postalCode(@Nullable Output<String> postalCode) {
            $.postalCode = postalCode;
            return this;
        }

        /**
         * @param postalCode (Updatable) Post code of the address.
         * 
         * @return builder
         * 
         */
        public Builder postalCode(String postalCode) {
            return postalCode(Output.of(postalCode));
        }

        /**
         * @param state (Updatable) State of the address.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable Output<String> state) {
            $.state = state;
            return this;
        }

        /**
         * @param state (Updatable) State of the address.
         * 
         * @return builder
         * 
         */
        public Builder state(String state) {
            return state(Output.of(state));
        }

        public SubscriptionSubscriptionBillingAddressArgs build() {
            return $;
        }
    }

}
