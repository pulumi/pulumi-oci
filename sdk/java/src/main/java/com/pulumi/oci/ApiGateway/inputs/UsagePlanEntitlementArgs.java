// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ApiGateway.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.ApiGateway.inputs.UsagePlanEntitlementQuotaArgs;
import com.pulumi.oci.ApiGateway.inputs.UsagePlanEntitlementRateLimitArgs;
import com.pulumi.oci.ApiGateway.inputs.UsagePlanEntitlementTargetArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class UsagePlanEntitlementArgs extends com.pulumi.resources.ResourceArgs {

    public static final UsagePlanEntitlementArgs Empty = new UsagePlanEntitlementArgs();

    /**
     * (Updatable) A user-friendly description. To provide some insight about the resource. Avoid entering confidential information.
     * 
     */
    @Import(name="description")
    private @Nullable Output<String> description;

    /**
     * @return (Updatable) A user-friendly description. To provide some insight about the resource. Avoid entering confidential information.
     * 
     */
    public Optional<Output<String>> description() {
        return Optional.ofNullable(this.description);
    }

    /**
     * (Updatable) An entitlement name, unique within a usage plan.
     * 
     */
    @Import(name="name", required=true)
    private Output<String> name;

    /**
     * @return (Updatable) An entitlement name, unique within a usage plan.
     * 
     */
    public Output<String> name() {
        return this.name;
    }

    /**
     * (Updatable) Quota policy for a usage plan.
     * 
     */
    @Import(name="quota")
    private @Nullable Output<UsagePlanEntitlementQuotaArgs> quota;

    /**
     * @return (Updatable) Quota policy for a usage plan.
     * 
     */
    public Optional<Output<UsagePlanEntitlementQuotaArgs>> quota() {
        return Optional.ofNullable(this.quota);
    }

    /**
     * (Updatable) Rate-limiting policy for a usage plan.
     * 
     */
    @Import(name="rateLimit")
    private @Nullable Output<UsagePlanEntitlementRateLimitArgs> rateLimit;

    /**
     * @return (Updatable) Rate-limiting policy for a usage plan.
     * 
     */
    public Optional<Output<UsagePlanEntitlementRateLimitArgs>> rateLimit() {
        return Optional.ofNullable(this.rateLimit);
    }

    /**
     * (Updatable) A collection of targeted deployments that the entitlement will be applied to.
     * 
     */
    @Import(name="targets")
    private @Nullable Output<List<UsagePlanEntitlementTargetArgs>> targets;

    /**
     * @return (Updatable) A collection of targeted deployments that the entitlement will be applied to.
     * 
     */
    public Optional<Output<List<UsagePlanEntitlementTargetArgs>>> targets() {
        return Optional.ofNullable(this.targets);
    }

    private UsagePlanEntitlementArgs() {}

    private UsagePlanEntitlementArgs(UsagePlanEntitlementArgs $) {
        this.description = $.description;
        this.name = $.name;
        this.quota = $.quota;
        this.rateLimit = $.rateLimit;
        this.targets = $.targets;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(UsagePlanEntitlementArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private UsagePlanEntitlementArgs $;

        public Builder() {
            $ = new UsagePlanEntitlementArgs();
        }

        public Builder(UsagePlanEntitlementArgs defaults) {
            $ = new UsagePlanEntitlementArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param description (Updatable) A user-friendly description. To provide some insight about the resource. Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder description(@Nullable Output<String> description) {
            $.description = description;
            return this;
        }

        /**
         * @param description (Updatable) A user-friendly description. To provide some insight about the resource. Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder description(String description) {
            return description(Output.of(description));
        }

        /**
         * @param name (Updatable) An entitlement name, unique within a usage plan.
         * 
         * @return builder
         * 
         */
        public Builder name(Output<String> name) {
            $.name = name;
            return this;
        }

        /**
         * @param name (Updatable) An entitlement name, unique within a usage plan.
         * 
         * @return builder
         * 
         */
        public Builder name(String name) {
            return name(Output.of(name));
        }

        /**
         * @param quota (Updatable) Quota policy for a usage plan.
         * 
         * @return builder
         * 
         */
        public Builder quota(@Nullable Output<UsagePlanEntitlementQuotaArgs> quota) {
            $.quota = quota;
            return this;
        }

        /**
         * @param quota (Updatable) Quota policy for a usage plan.
         * 
         * @return builder
         * 
         */
        public Builder quota(UsagePlanEntitlementQuotaArgs quota) {
            return quota(Output.of(quota));
        }

        /**
         * @param rateLimit (Updatable) Rate-limiting policy for a usage plan.
         * 
         * @return builder
         * 
         */
        public Builder rateLimit(@Nullable Output<UsagePlanEntitlementRateLimitArgs> rateLimit) {
            $.rateLimit = rateLimit;
            return this;
        }

        /**
         * @param rateLimit (Updatable) Rate-limiting policy for a usage plan.
         * 
         * @return builder
         * 
         */
        public Builder rateLimit(UsagePlanEntitlementRateLimitArgs rateLimit) {
            return rateLimit(Output.of(rateLimit));
        }

        /**
         * @param targets (Updatable) A collection of targeted deployments that the entitlement will be applied to.
         * 
         * @return builder
         * 
         */
        public Builder targets(@Nullable Output<List<UsagePlanEntitlementTargetArgs>> targets) {
            $.targets = targets;
            return this;
        }

        /**
         * @param targets (Updatable) A collection of targeted deployments that the entitlement will be applied to.
         * 
         * @return builder
         * 
         */
        public Builder targets(List<UsagePlanEntitlementTargetArgs> targets) {
            return targets(Output.of(targets));
        }

        /**
         * @param targets (Updatable) A collection of targeted deployments that the entitlement will be applied to.
         * 
         * @return builder
         * 
         */
        public Builder targets(UsagePlanEntitlementTargetArgs... targets) {
            return targets(List.of(targets));
        }

        public UsagePlanEntitlementArgs build() {
            $.name = Objects.requireNonNull($.name, "expected parameter 'name' to be non-null");
            return $;
        }
    }

}