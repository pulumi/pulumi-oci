// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Email.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class SuppressionState extends com.pulumi.resources.ResourceArgs {

    public static final SuppressionState Empty = new SuppressionState();

    /**
     * The OCID of the compartment to contain the suppression. Since suppressions are at the customer level, this must be the tenancy OCID.
     * 
     */
    @Import(name="compartmentId")
    private @Nullable Output<String> compartmentId;

    /**
     * @return The OCID of the compartment to contain the suppression. Since suppressions are at the customer level, this must be the tenancy OCID.
     * 
     */
    public Optional<Output<String>> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
    }

    /**
     * The recipient email address of the suppression.
     * 
     */
    @Import(name="emailAddress")
    private @Nullable Output<String> emailAddress;

    /**
     * @return The recipient email address of the suppression.
     * 
     */
    public Optional<Output<String>> emailAddress() {
        return Optional.ofNullable(this.emailAddress);
    }

    /**
     * The specific error message returned by a system that resulted in the suppression. This message is usually an SMTP error code with additional descriptive text. Not provided for all types of suppressions.
     * 
     */
    @Import(name="errorDetail")
    private @Nullable Output<String> errorDetail;

    /**
     * @return The specific error message returned by a system that resulted in the suppression. This message is usually an SMTP error code with additional descriptive text. Not provided for all types of suppressions.
     * 
     */
    public Optional<Output<String>> errorDetail() {
        return Optional.ofNullable(this.errorDetail);
    }

    /**
     * DNS name of the source of the error that caused the suppression. Will be set to either the remote-mta or reporting-mta field from a delivery status notification (RFC 3464) when available. Not provided for all types of suppressions, and not always known.
     * 
     */
    @Import(name="errorSource")
    private @Nullable Output<String> errorSource;

    /**
     * @return DNS name of the source of the error that caused the suppression. Will be set to either the remote-mta or reporting-mta field from a delivery status notification (RFC 3464) when available. Not provided for all types of suppressions, and not always known.
     * 
     */
    public Optional<Output<String>> errorSource() {
        return Optional.ofNullable(this.errorSource);
    }

    /**
     * The value of the Message-ID header from the email that triggered a suppression. This value is as defined in RFC 5322 section 3.6.4, excluding angle-brackets. Not provided for all types of suppressions.
     * 
     */
    @Import(name="messageId")
    private @Nullable Output<String> messageId;

    /**
     * @return The value of the Message-ID header from the email that triggered a suppression. This value is as defined in RFC 5322 section 3.6.4, excluding angle-brackets. Not provided for all types of suppressions.
     * 
     */
    public Optional<Output<String>> messageId() {
        return Optional.ofNullable(this.messageId);
    }

    /**
     * The reason that the email address was suppressed. For more information on the types of bounces, see [Suppression List](https://docs.cloud.oracle.com/iaas/Content/Email/Concepts/overview.htm#components).
     * 
     */
    @Import(name="reason")
    private @Nullable Output<String> reason;

    /**
     * @return The reason that the email address was suppressed. For more information on the types of bounces, see [Suppression List](https://docs.cloud.oracle.com/iaas/Content/Email/Concepts/overview.htm#components).
     * 
     */
    public Optional<Output<String>> reason() {
        return Optional.ofNullable(this.reason);
    }

    /**
     * The date and time a recipient&#39;s email address was added to the suppression list, in &#34;YYYY-MM-ddThh:mmZ&#34; format with a Z offset, as defined by RFC 3339.
     * 
     */
    @Import(name="timeCreated")
    private @Nullable Output<String> timeCreated;

    /**
     * @return The date and time a recipient&#39;s email address was added to the suppression list, in &#34;YYYY-MM-ddThh:mmZ&#34; format with a Z offset, as defined by RFC 3339.
     * 
     */
    public Optional<Output<String>> timeCreated() {
        return Optional.ofNullable(this.timeCreated);
    }

    /**
     * The last date and time the suppression prevented submission in &#34;YYYY-MM-ddThh:mmZ&#34; format with a Z offset, as defined by RFC 3339.
     * 
     */
    @Import(name="timeLastSuppressed")
    private @Nullable Output<String> timeLastSuppressed;

    /**
     * @return The last date and time the suppression prevented submission in &#34;YYYY-MM-ddThh:mmZ&#34; format with a Z offset, as defined by RFC 3339.
     * 
     */
    public Optional<Output<String>> timeLastSuppressed() {
        return Optional.ofNullable(this.timeLastSuppressed);
    }

    private SuppressionState() {}

    private SuppressionState(SuppressionState $) {
        this.compartmentId = $.compartmentId;
        this.emailAddress = $.emailAddress;
        this.errorDetail = $.errorDetail;
        this.errorSource = $.errorSource;
        this.messageId = $.messageId;
        this.reason = $.reason;
        this.timeCreated = $.timeCreated;
        this.timeLastSuppressed = $.timeLastSuppressed;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(SuppressionState defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private SuppressionState $;

        public Builder() {
            $ = new SuppressionState();
        }

        public Builder(SuppressionState defaults) {
            $ = new SuppressionState(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId The OCID of the compartment to contain the suppression. Since suppressions are at the customer level, this must be the tenancy OCID.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(@Nullable Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId The OCID of the compartment to contain the suppression. Since suppressions are at the customer level, this must be the tenancy OCID.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param emailAddress The recipient email address of the suppression.
         * 
         * @return builder
         * 
         */
        public Builder emailAddress(@Nullable Output<String> emailAddress) {
            $.emailAddress = emailAddress;
            return this;
        }

        /**
         * @param emailAddress The recipient email address of the suppression.
         * 
         * @return builder
         * 
         */
        public Builder emailAddress(String emailAddress) {
            return emailAddress(Output.of(emailAddress));
        }

        /**
         * @param errorDetail The specific error message returned by a system that resulted in the suppression. This message is usually an SMTP error code with additional descriptive text. Not provided for all types of suppressions.
         * 
         * @return builder
         * 
         */
        public Builder errorDetail(@Nullable Output<String> errorDetail) {
            $.errorDetail = errorDetail;
            return this;
        }

        /**
         * @param errorDetail The specific error message returned by a system that resulted in the suppression. This message is usually an SMTP error code with additional descriptive text. Not provided for all types of suppressions.
         * 
         * @return builder
         * 
         */
        public Builder errorDetail(String errorDetail) {
            return errorDetail(Output.of(errorDetail));
        }

        /**
         * @param errorSource DNS name of the source of the error that caused the suppression. Will be set to either the remote-mta or reporting-mta field from a delivery status notification (RFC 3464) when available. Not provided for all types of suppressions, and not always known.
         * 
         * @return builder
         * 
         */
        public Builder errorSource(@Nullable Output<String> errorSource) {
            $.errorSource = errorSource;
            return this;
        }

        /**
         * @param errorSource DNS name of the source of the error that caused the suppression. Will be set to either the remote-mta or reporting-mta field from a delivery status notification (RFC 3464) when available. Not provided for all types of suppressions, and not always known.
         * 
         * @return builder
         * 
         */
        public Builder errorSource(String errorSource) {
            return errorSource(Output.of(errorSource));
        }

        /**
         * @param messageId The value of the Message-ID header from the email that triggered a suppression. This value is as defined in RFC 5322 section 3.6.4, excluding angle-brackets. Not provided for all types of suppressions.
         * 
         * @return builder
         * 
         */
        public Builder messageId(@Nullable Output<String> messageId) {
            $.messageId = messageId;
            return this;
        }

        /**
         * @param messageId The value of the Message-ID header from the email that triggered a suppression. This value is as defined in RFC 5322 section 3.6.4, excluding angle-brackets. Not provided for all types of suppressions.
         * 
         * @return builder
         * 
         */
        public Builder messageId(String messageId) {
            return messageId(Output.of(messageId));
        }

        /**
         * @param reason The reason that the email address was suppressed. For more information on the types of bounces, see [Suppression List](https://docs.cloud.oracle.com/iaas/Content/Email/Concepts/overview.htm#components).
         * 
         * @return builder
         * 
         */
        public Builder reason(@Nullable Output<String> reason) {
            $.reason = reason;
            return this;
        }

        /**
         * @param reason The reason that the email address was suppressed. For more information on the types of bounces, see [Suppression List](https://docs.cloud.oracle.com/iaas/Content/Email/Concepts/overview.htm#components).
         * 
         * @return builder
         * 
         */
        public Builder reason(String reason) {
            return reason(Output.of(reason));
        }

        /**
         * @param timeCreated The date and time a recipient&#39;s email address was added to the suppression list, in &#34;YYYY-MM-ddThh:mmZ&#34; format with a Z offset, as defined by RFC 3339.
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(@Nullable Output<String> timeCreated) {
            $.timeCreated = timeCreated;
            return this;
        }

        /**
         * @param timeCreated The date and time a recipient&#39;s email address was added to the suppression list, in &#34;YYYY-MM-ddThh:mmZ&#34; format with a Z offset, as defined by RFC 3339.
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(String timeCreated) {
            return timeCreated(Output.of(timeCreated));
        }

        /**
         * @param timeLastSuppressed The last date and time the suppression prevented submission in &#34;YYYY-MM-ddThh:mmZ&#34; format with a Z offset, as defined by RFC 3339.
         * 
         * @return builder
         * 
         */
        public Builder timeLastSuppressed(@Nullable Output<String> timeLastSuppressed) {
            $.timeLastSuppressed = timeLastSuppressed;
            return this;
        }

        /**
         * @param timeLastSuppressed The last date and time the suppression prevented submission in &#34;YYYY-MM-ddThh:mmZ&#34; format with a Z offset, as defined by RFC 3339.
         * 
         * @return builder
         * 
         */
        public Builder timeLastSuppressed(String timeLastSuppressed) {
            return timeLastSuppressed(Output.of(timeLastSuppressed));
        }

        public SuppressionState build() {
            return $;
        }
    }

}