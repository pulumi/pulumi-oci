// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Vault.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.Boolean;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class SecretSecretRuleArgs extends com.pulumi.resources.ResourceArgs {

    public static final SecretSecretRuleArgs Empty = new SecretSecretRuleArgs();

    /**
     * (Updatable) A property indicating whether the rule is applied even if the secret version with the content you are trying to reuse was deleted.
     * 
     */
    @Import(name="isEnforcedOnDeletedSecretVersions")
    private @Nullable Output<Boolean> isEnforcedOnDeletedSecretVersions;

    /**
     * @return (Updatable) A property indicating whether the rule is applied even if the secret version with the content you are trying to reuse was deleted.
     * 
     */
    public Optional<Output<Boolean>> isEnforcedOnDeletedSecretVersions() {
        return Optional.ofNullable(this.isEnforcedOnDeletedSecretVersions);
    }

    /**
     * (Updatable) A property indicating whether to block retrieval of the secret content, on expiry. The default is false. If the secret has already expired and you would like to retrieve the secret contents, you need to edit the secret rule to disable this property, to allow reading the secret content.
     * 
     */
    @Import(name="isSecretContentRetrievalBlockedOnExpiry")
    private @Nullable Output<Boolean> isSecretContentRetrievalBlockedOnExpiry;

    /**
     * @return (Updatable) A property indicating whether to block retrieval of the secret content, on expiry. The default is false. If the secret has already expired and you would like to retrieve the secret contents, you need to edit the secret rule to disable this property, to allow reading the secret content.
     * 
     */
    public Optional<Output<Boolean>> isSecretContentRetrievalBlockedOnExpiry() {
        return Optional.ofNullable(this.isSecretContentRetrievalBlockedOnExpiry);
    }

    /**
     * (Updatable) The type of rule, which either controls when the secret contents expire or whether they can be reused.
     * 
     */
    @Import(name="ruleType", required=true)
    private Output<String> ruleType;

    /**
     * @return (Updatable) The type of rule, which either controls when the secret contents expire or whether they can be reused.
     * 
     */
    public Output<String> ruleType() {
        return this.ruleType;
    }

    /**
     * (Updatable) A property indicating how long the secret contents will be considered valid, expressed in [ISO 8601](https://en.wikipedia.org/wiki/ISO_8601#Time_intervals) format. The secret needs to be updated when the secret content expires. No enforcement mechanism exists at this time, but audit logs record the expiration on the appropriate date, according to the time interval specified in the rule. The timer resets after you update the secret contents. The minimum value is 1 day and the maximum value is 90 days for this property. Currently, only intervals expressed in days are supported. For example, pass `P3D` to have the secret version expire every 3 days.
     * 
     */
    @Import(name="secretVersionExpiryInterval")
    private @Nullable Output<String> secretVersionExpiryInterval;

    /**
     * @return (Updatable) A property indicating how long the secret contents will be considered valid, expressed in [ISO 8601](https://en.wikipedia.org/wiki/ISO_8601#Time_intervals) format. The secret needs to be updated when the secret content expires. No enforcement mechanism exists at this time, but audit logs record the expiration on the appropriate date, according to the time interval specified in the rule. The timer resets after you update the secret contents. The minimum value is 1 day and the maximum value is 90 days for this property. Currently, only intervals expressed in days are supported. For example, pass `P3D` to have the secret version expire every 3 days.
     * 
     */
    public Optional<Output<String>> secretVersionExpiryInterval() {
        return Optional.ofNullable(this.secretVersionExpiryInterval);
    }

    /**
     * (Updatable) An optional property indicating the absolute time when this secret will expire, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. The minimum number of days from current time is 1 day and the maximum number of days from current time is 365 days. Example: `2019-04-03T21:10:29.600Z`
     * 
     */
    @Import(name="timeOfAbsoluteExpiry")
    private @Nullable Output<String> timeOfAbsoluteExpiry;

    /**
     * @return (Updatable) An optional property indicating the absolute time when this secret will expire, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. The minimum number of days from current time is 1 day and the maximum number of days from current time is 365 days. Example: `2019-04-03T21:10:29.600Z`
     * 
     */
    public Optional<Output<String>> timeOfAbsoluteExpiry() {
        return Optional.ofNullable(this.timeOfAbsoluteExpiry);
    }

    private SecretSecretRuleArgs() {}

    private SecretSecretRuleArgs(SecretSecretRuleArgs $) {
        this.isEnforcedOnDeletedSecretVersions = $.isEnforcedOnDeletedSecretVersions;
        this.isSecretContentRetrievalBlockedOnExpiry = $.isSecretContentRetrievalBlockedOnExpiry;
        this.ruleType = $.ruleType;
        this.secretVersionExpiryInterval = $.secretVersionExpiryInterval;
        this.timeOfAbsoluteExpiry = $.timeOfAbsoluteExpiry;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(SecretSecretRuleArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private SecretSecretRuleArgs $;

        public Builder() {
            $ = new SecretSecretRuleArgs();
        }

        public Builder(SecretSecretRuleArgs defaults) {
            $ = new SecretSecretRuleArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param isEnforcedOnDeletedSecretVersions (Updatable) A property indicating whether the rule is applied even if the secret version with the content you are trying to reuse was deleted.
         * 
         * @return builder
         * 
         */
        public Builder isEnforcedOnDeletedSecretVersions(@Nullable Output<Boolean> isEnforcedOnDeletedSecretVersions) {
            $.isEnforcedOnDeletedSecretVersions = isEnforcedOnDeletedSecretVersions;
            return this;
        }

        /**
         * @param isEnforcedOnDeletedSecretVersions (Updatable) A property indicating whether the rule is applied even if the secret version with the content you are trying to reuse was deleted.
         * 
         * @return builder
         * 
         */
        public Builder isEnforcedOnDeletedSecretVersions(Boolean isEnforcedOnDeletedSecretVersions) {
            return isEnforcedOnDeletedSecretVersions(Output.of(isEnforcedOnDeletedSecretVersions));
        }

        /**
         * @param isSecretContentRetrievalBlockedOnExpiry (Updatable) A property indicating whether to block retrieval of the secret content, on expiry. The default is false. If the secret has already expired and you would like to retrieve the secret contents, you need to edit the secret rule to disable this property, to allow reading the secret content.
         * 
         * @return builder
         * 
         */
        public Builder isSecretContentRetrievalBlockedOnExpiry(@Nullable Output<Boolean> isSecretContentRetrievalBlockedOnExpiry) {
            $.isSecretContentRetrievalBlockedOnExpiry = isSecretContentRetrievalBlockedOnExpiry;
            return this;
        }

        /**
         * @param isSecretContentRetrievalBlockedOnExpiry (Updatable) A property indicating whether to block retrieval of the secret content, on expiry. The default is false. If the secret has already expired and you would like to retrieve the secret contents, you need to edit the secret rule to disable this property, to allow reading the secret content.
         * 
         * @return builder
         * 
         */
        public Builder isSecretContentRetrievalBlockedOnExpiry(Boolean isSecretContentRetrievalBlockedOnExpiry) {
            return isSecretContentRetrievalBlockedOnExpiry(Output.of(isSecretContentRetrievalBlockedOnExpiry));
        }

        /**
         * @param ruleType (Updatable) The type of rule, which either controls when the secret contents expire or whether they can be reused.
         * 
         * @return builder
         * 
         */
        public Builder ruleType(Output<String> ruleType) {
            $.ruleType = ruleType;
            return this;
        }

        /**
         * @param ruleType (Updatable) The type of rule, which either controls when the secret contents expire or whether they can be reused.
         * 
         * @return builder
         * 
         */
        public Builder ruleType(String ruleType) {
            return ruleType(Output.of(ruleType));
        }

        /**
         * @param secretVersionExpiryInterval (Updatable) A property indicating how long the secret contents will be considered valid, expressed in [ISO 8601](https://en.wikipedia.org/wiki/ISO_8601#Time_intervals) format. The secret needs to be updated when the secret content expires. No enforcement mechanism exists at this time, but audit logs record the expiration on the appropriate date, according to the time interval specified in the rule. The timer resets after you update the secret contents. The minimum value is 1 day and the maximum value is 90 days for this property. Currently, only intervals expressed in days are supported. For example, pass `P3D` to have the secret version expire every 3 days.
         * 
         * @return builder
         * 
         */
        public Builder secretVersionExpiryInterval(@Nullable Output<String> secretVersionExpiryInterval) {
            $.secretVersionExpiryInterval = secretVersionExpiryInterval;
            return this;
        }

        /**
         * @param secretVersionExpiryInterval (Updatable) A property indicating how long the secret contents will be considered valid, expressed in [ISO 8601](https://en.wikipedia.org/wiki/ISO_8601#Time_intervals) format. The secret needs to be updated when the secret content expires. No enforcement mechanism exists at this time, but audit logs record the expiration on the appropriate date, according to the time interval specified in the rule. The timer resets after you update the secret contents. The minimum value is 1 day and the maximum value is 90 days for this property. Currently, only intervals expressed in days are supported. For example, pass `P3D` to have the secret version expire every 3 days.
         * 
         * @return builder
         * 
         */
        public Builder secretVersionExpiryInterval(String secretVersionExpiryInterval) {
            return secretVersionExpiryInterval(Output.of(secretVersionExpiryInterval));
        }

        /**
         * @param timeOfAbsoluteExpiry (Updatable) An optional property indicating the absolute time when this secret will expire, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. The minimum number of days from current time is 1 day and the maximum number of days from current time is 365 days. Example: `2019-04-03T21:10:29.600Z`
         * 
         * @return builder
         * 
         */
        public Builder timeOfAbsoluteExpiry(@Nullable Output<String> timeOfAbsoluteExpiry) {
            $.timeOfAbsoluteExpiry = timeOfAbsoluteExpiry;
            return this;
        }

        /**
         * @param timeOfAbsoluteExpiry (Updatable) An optional property indicating the absolute time when this secret will expire, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. The minimum number of days from current time is 1 day and the maximum number of days from current time is 365 days. Example: `2019-04-03T21:10:29.600Z`
         * 
         * @return builder
         * 
         */
        public Builder timeOfAbsoluteExpiry(String timeOfAbsoluteExpiry) {
            return timeOfAbsoluteExpiry(Output.of(timeOfAbsoluteExpiry));
        }

        public SecretSecretRuleArgs build() {
            $.ruleType = Objects.requireNonNull($.ruleType, "expected parameter 'ruleType' to be non-null");
            return $;
        }
    }

}