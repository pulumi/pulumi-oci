// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class DomainsNotificationSettingFromEmailAddressArgs extends com.pulumi.resources.ResourceArgs {

    public static final DomainsNotificationSettingFromEmailAddressArgs Empty = new DomainsNotificationSettingFromEmailAddressArgs();

    /**
     * (Updatable) Display name for the From email address
     * 
     * **Added In:** 19.2.1
     * 
     * **SCIM++ Properties:**
     * * idcsSearchable: false
     * * multiValued: false
     * * mutability: readWrite
     * * required: false
     * * returned: default
     * * type: string
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return (Updatable) Display name for the From email address
     * 
     * **Added In:** 19.2.1
     * 
     * **SCIM++ Properties:**
     * * idcsSearchable: false
     * * multiValued: false
     * * mutability: readWrite
     * * required: false
     * * returned: default
     * * type: string
     * 
     */
    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    /**
     * (Updatable) From address verification mode. If postmaster account is available then &#39;domain&#39; mode is used or entire valid email can be verified using &#39;email&#39; mode
     * 
     * **Added In:** 18.2.6
     * 
     * **SCIM++ Properties:**
     * * caseExact: false
     * * idcsSearchable: false
     * * multiValued: false
     * * mutability: readWrite
     * * required: true
     * * returned: default
     * * type: string
     * * uniqueness: none
     * 
     */
    @Import(name="validate", required=true)
    private Output<String> validate;

    /**
     * @return (Updatable) From address verification mode. If postmaster account is available then &#39;domain&#39; mode is used or entire valid email can be verified using &#39;email&#39; mode
     * 
     * **Added In:** 18.2.6
     * 
     * **SCIM++ Properties:**
     * * caseExact: false
     * * idcsSearchable: false
     * * multiValued: false
     * * mutability: readWrite
     * * required: true
     * * returned: default
     * * type: string
     * * uniqueness: none
     * 
     */
    public Output<String> validate() {
        return this.validate;
    }

    /**
     * (Updatable) Validation status for the From email address
     * 
     * **SCIM++ Properties:**
     * * multiValued: false
     * * mutability: readOnly
     * * required: false
     * * returned: default
     * * type: string
     * 
     */
    @Import(name="validationStatus")
    private @Nullable Output<String> validationStatus;

    /**
     * @return (Updatable) Validation status for the From email address
     * 
     * **SCIM++ Properties:**
     * * multiValued: false
     * * mutability: readOnly
     * * required: false
     * * returned: default
     * * type: string
     * 
     */
    public Optional<Output<String>> validationStatus() {
        return Optional.ofNullable(this.validationStatus);
    }

    /**
     * (Updatable) Value of the From email address
     * 
     * **SCIM++ Properties:**
     * * multiValued: false
     * * mutability: readWrite
     * * required: true
     * * returned: default
     * * type: string
     * 
     */
    @Import(name="value", required=true)
    private Output<String> value;

    /**
     * @return (Updatable) Value of the From email address
     * 
     * **SCIM++ Properties:**
     * * multiValued: false
     * * mutability: readWrite
     * * required: true
     * * returned: default
     * * type: string
     * 
     */
    public Output<String> value() {
        return this.value;
    }

    private DomainsNotificationSettingFromEmailAddressArgs() {}

    private DomainsNotificationSettingFromEmailAddressArgs(DomainsNotificationSettingFromEmailAddressArgs $) {
        this.displayName = $.displayName;
        this.validate = $.validate;
        this.validationStatus = $.validationStatus;
        this.value = $.value;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(DomainsNotificationSettingFromEmailAddressArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private DomainsNotificationSettingFromEmailAddressArgs $;

        public Builder() {
            $ = new DomainsNotificationSettingFromEmailAddressArgs();
        }

        public Builder(DomainsNotificationSettingFromEmailAddressArgs defaults) {
            $ = new DomainsNotificationSettingFromEmailAddressArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param displayName (Updatable) Display name for the From email address
         * 
         * **Added In:** 19.2.1
         * 
         * **SCIM++ Properties:**
         * * idcsSearchable: false
         * * multiValued: false
         * * mutability: readWrite
         * * required: false
         * * returned: default
         * * type: string
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName (Updatable) Display name for the From email address
         * 
         * **Added In:** 19.2.1
         * 
         * **SCIM++ Properties:**
         * * idcsSearchable: false
         * * multiValued: false
         * * mutability: readWrite
         * * required: false
         * * returned: default
         * * type: string
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        /**
         * @param validate (Updatable) From address verification mode. If postmaster account is available then &#39;domain&#39; mode is used or entire valid email can be verified using &#39;email&#39; mode
         * 
         * **Added In:** 18.2.6
         * 
         * **SCIM++ Properties:**
         * * caseExact: false
         * * idcsSearchable: false
         * * multiValued: false
         * * mutability: readWrite
         * * required: true
         * * returned: default
         * * type: string
         * * uniqueness: none
         * 
         * @return builder
         * 
         */
        public Builder validate(Output<String> validate) {
            $.validate = validate;
            return this;
        }

        /**
         * @param validate (Updatable) From address verification mode. If postmaster account is available then &#39;domain&#39; mode is used or entire valid email can be verified using &#39;email&#39; mode
         * 
         * **Added In:** 18.2.6
         * 
         * **SCIM++ Properties:**
         * * caseExact: false
         * * idcsSearchable: false
         * * multiValued: false
         * * mutability: readWrite
         * * required: true
         * * returned: default
         * * type: string
         * * uniqueness: none
         * 
         * @return builder
         * 
         */
        public Builder validate(String validate) {
            return validate(Output.of(validate));
        }

        /**
         * @param validationStatus (Updatable) Validation status for the From email address
         * 
         * **SCIM++ Properties:**
         * * multiValued: false
         * * mutability: readOnly
         * * required: false
         * * returned: default
         * * type: string
         * 
         * @return builder
         * 
         */
        public Builder validationStatus(@Nullable Output<String> validationStatus) {
            $.validationStatus = validationStatus;
            return this;
        }

        /**
         * @param validationStatus (Updatable) Validation status for the From email address
         * 
         * **SCIM++ Properties:**
         * * multiValued: false
         * * mutability: readOnly
         * * required: false
         * * returned: default
         * * type: string
         * 
         * @return builder
         * 
         */
        public Builder validationStatus(String validationStatus) {
            return validationStatus(Output.of(validationStatus));
        }

        /**
         * @param value (Updatable) Value of the From email address
         * 
         * **SCIM++ Properties:**
         * * multiValued: false
         * * mutability: readWrite
         * * required: true
         * * returned: default
         * * type: string
         * 
         * @return builder
         * 
         */
        public Builder value(Output<String> value) {
            $.value = value;
            return this;
        }

        /**
         * @param value (Updatable) Value of the From email address
         * 
         * **SCIM++ Properties:**
         * * multiValued: false
         * * mutability: readWrite
         * * required: true
         * * returned: default
         * * type: string
         * 
         * @return builder
         * 
         */
        public Builder value(String value) {
            return value(Output.of(value));
        }

        public DomainsNotificationSettingFromEmailAddressArgs build() {
            if ($.validate == null) {
                throw new MissingRequiredPropertyException("DomainsNotificationSettingFromEmailAddressArgs", "validate");
            }
            if ($.value == null) {
                throw new MissingRequiredPropertyException("DomainsNotificationSettingFromEmailAddressArgs", "value");
            }
            return $;
        }
    }

}
