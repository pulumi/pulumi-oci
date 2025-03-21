// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Vault.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Vault.inputs.SecretRotationConfigTargetSystemDetailsArgs;
import java.lang.Boolean;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class SecretRotationConfigArgs extends com.pulumi.resources.ResourceArgs {

    public static final SecretRotationConfigArgs Empty = new SecretRotationConfigArgs();

    /**
     * (Updatable) Enables auto rotation, when set to true rotationInterval must be set.
     * 
     */
    @Import(name="isScheduledRotationEnabled")
    private @Nullable Output<Boolean> isScheduledRotationEnabled;

    /**
     * @return (Updatable) Enables auto rotation, when set to true rotationInterval must be set.
     * 
     */
    public Optional<Output<Boolean>> isScheduledRotationEnabled() {
        return Optional.ofNullable(this.isScheduledRotationEnabled);
    }

    /**
     * (Updatable) The time interval that indicates the frequency for rotating secret data, as described in ISO 8601 format. The minimum value is 1 day and maximum value is 360 days. For example, if you want to set the time interval for rotating a secret data as 30 days, the duration is expressed as &#34;P30D.&#34;
     * 
     */
    @Import(name="rotationInterval")
    private @Nullable Output<String> rotationInterval;

    /**
     * @return (Updatable) The time interval that indicates the frequency for rotating secret data, as described in ISO 8601 format. The minimum value is 1 day and maximum value is 360 days. For example, if you want to set the time interval for rotating a secret data as 30 days, the duration is expressed as &#34;P30D.&#34;
     * 
     */
    public Optional<Output<String>> rotationInterval() {
        return Optional.ofNullable(this.rotationInterval);
    }

    /**
     * (Updatable) The TargetSystemDetails provides the targetSystem type and type-specific connection metadata
     * 
     */
    @Import(name="targetSystemDetails", required=true)
    private Output<SecretRotationConfigTargetSystemDetailsArgs> targetSystemDetails;

    /**
     * @return (Updatable) The TargetSystemDetails provides the targetSystem type and type-specific connection metadata
     * 
     */
    public Output<SecretRotationConfigTargetSystemDetailsArgs> targetSystemDetails() {
        return this.targetSystemDetails;
    }

    private SecretRotationConfigArgs() {}

    private SecretRotationConfigArgs(SecretRotationConfigArgs $) {
        this.isScheduledRotationEnabled = $.isScheduledRotationEnabled;
        this.rotationInterval = $.rotationInterval;
        this.targetSystemDetails = $.targetSystemDetails;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(SecretRotationConfigArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private SecretRotationConfigArgs $;

        public Builder() {
            $ = new SecretRotationConfigArgs();
        }

        public Builder(SecretRotationConfigArgs defaults) {
            $ = new SecretRotationConfigArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param isScheduledRotationEnabled (Updatable) Enables auto rotation, when set to true rotationInterval must be set.
         * 
         * @return builder
         * 
         */
        public Builder isScheduledRotationEnabled(@Nullable Output<Boolean> isScheduledRotationEnabled) {
            $.isScheduledRotationEnabled = isScheduledRotationEnabled;
            return this;
        }

        /**
         * @param isScheduledRotationEnabled (Updatable) Enables auto rotation, when set to true rotationInterval must be set.
         * 
         * @return builder
         * 
         */
        public Builder isScheduledRotationEnabled(Boolean isScheduledRotationEnabled) {
            return isScheduledRotationEnabled(Output.of(isScheduledRotationEnabled));
        }

        /**
         * @param rotationInterval (Updatable) The time interval that indicates the frequency for rotating secret data, as described in ISO 8601 format. The minimum value is 1 day and maximum value is 360 days. For example, if you want to set the time interval for rotating a secret data as 30 days, the duration is expressed as &#34;P30D.&#34;
         * 
         * @return builder
         * 
         */
        public Builder rotationInterval(@Nullable Output<String> rotationInterval) {
            $.rotationInterval = rotationInterval;
            return this;
        }

        /**
         * @param rotationInterval (Updatable) The time interval that indicates the frequency for rotating secret data, as described in ISO 8601 format. The minimum value is 1 day and maximum value is 360 days. For example, if you want to set the time interval for rotating a secret data as 30 days, the duration is expressed as &#34;P30D.&#34;
         * 
         * @return builder
         * 
         */
        public Builder rotationInterval(String rotationInterval) {
            return rotationInterval(Output.of(rotationInterval));
        }

        /**
         * @param targetSystemDetails (Updatable) The TargetSystemDetails provides the targetSystem type and type-specific connection metadata
         * 
         * @return builder
         * 
         */
        public Builder targetSystemDetails(Output<SecretRotationConfigTargetSystemDetailsArgs> targetSystemDetails) {
            $.targetSystemDetails = targetSystemDetails;
            return this;
        }

        /**
         * @param targetSystemDetails (Updatable) The TargetSystemDetails provides the targetSystem type and type-specific connection metadata
         * 
         * @return builder
         * 
         */
        public Builder targetSystemDetails(SecretRotationConfigTargetSystemDetailsArgs targetSystemDetails) {
            return targetSystemDetails(Output.of(targetSystemDetails));
        }

        public SecretRotationConfigArgs build() {
            if ($.targetSystemDetails == null) {
                throw new MissingRequiredPropertyException("SecretRotationConfigArgs", "targetSystemDetails");
            }
            return $;
        }
    }

}
