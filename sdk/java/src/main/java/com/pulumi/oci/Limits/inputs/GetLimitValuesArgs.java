// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Limits.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.Limits.inputs.GetLimitValuesFilterArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetLimitValuesArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetLimitValuesArgs Empty = new GetLimitValuesArgs();

    /**
     * Filter entries by availability domain. This implies that only AD-specific values are returned.
     * 
     */
    @Import(name="availabilityDomain")
    private @Nullable Output<String> availabilityDomain;

    /**
     * @return Filter entries by availability domain. This implies that only AD-specific values are returned.
     * 
     */
    public Optional<Output<String>> availabilityDomain() {
        return Optional.ofNullable(this.availabilityDomain);
    }

    /**
     * The OCID of the parent compartment (remember that the tenancy is simply the root compartment).
     * 
     */
    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    /**
     * @return The OCID of the parent compartment (remember that the tenancy is simply the root compartment).
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }

    @Import(name="filters")
    private @Nullable Output<List<GetLimitValuesFilterArgs>> filters;

    public Optional<Output<List<GetLimitValuesFilterArgs>>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * Optional field, can be used to see a specific resource limit value.
     * 
     */
    @Import(name="name")
    private @Nullable Output<String> name;

    /**
     * @return Optional field, can be used to see a specific resource limit value.
     * 
     */
    public Optional<Output<String>> name() {
        return Optional.ofNullable(this.name);
    }

    /**
     * Filter entries by scope type.
     * 
     */
    @Import(name="scopeType")
    private @Nullable Output<String> scopeType;

    /**
     * @return Filter entries by scope type.
     * 
     */
    public Optional<Output<String>> scopeType() {
        return Optional.ofNullable(this.scopeType);
    }

    /**
     * The target service name.
     * 
     */
    @Import(name="serviceName", required=true)
    private Output<String> serviceName;

    /**
     * @return The target service name.
     * 
     */
    public Output<String> serviceName() {
        return this.serviceName;
    }

    private GetLimitValuesArgs() {}

    private GetLimitValuesArgs(GetLimitValuesArgs $) {
        this.availabilityDomain = $.availabilityDomain;
        this.compartmentId = $.compartmentId;
        this.filters = $.filters;
        this.name = $.name;
        this.scopeType = $.scopeType;
        this.serviceName = $.serviceName;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetLimitValuesArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetLimitValuesArgs $;

        public Builder() {
            $ = new GetLimitValuesArgs();
        }

        public Builder(GetLimitValuesArgs defaults) {
            $ = new GetLimitValuesArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param availabilityDomain Filter entries by availability domain. This implies that only AD-specific values are returned.
         * 
         * @return builder
         * 
         */
        public Builder availabilityDomain(@Nullable Output<String> availabilityDomain) {
            $.availabilityDomain = availabilityDomain;
            return this;
        }

        /**
         * @param availabilityDomain Filter entries by availability domain. This implies that only AD-specific values are returned.
         * 
         * @return builder
         * 
         */
        public Builder availabilityDomain(String availabilityDomain) {
            return availabilityDomain(Output.of(availabilityDomain));
        }

        /**
         * @param compartmentId The OCID of the parent compartment (remember that the tenancy is simply the root compartment).
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId The OCID of the parent compartment (remember that the tenancy is simply the root compartment).
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        public Builder filters(@Nullable Output<List<GetLimitValuesFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(List<GetLimitValuesFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        public Builder filters(GetLimitValuesFilterArgs... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param name Optional field, can be used to see a specific resource limit value.
         * 
         * @return builder
         * 
         */
        public Builder name(@Nullable Output<String> name) {
            $.name = name;
            return this;
        }

        /**
         * @param name Optional field, can be used to see a specific resource limit value.
         * 
         * @return builder
         * 
         */
        public Builder name(String name) {
            return name(Output.of(name));
        }

        /**
         * @param scopeType Filter entries by scope type.
         * 
         * @return builder
         * 
         */
        public Builder scopeType(@Nullable Output<String> scopeType) {
            $.scopeType = scopeType;
            return this;
        }

        /**
         * @param scopeType Filter entries by scope type.
         * 
         * @return builder
         * 
         */
        public Builder scopeType(String scopeType) {
            return scopeType(Output.of(scopeType));
        }

        /**
         * @param serviceName The target service name.
         * 
         * @return builder
         * 
         */
        public Builder serviceName(Output<String> serviceName) {
            $.serviceName = serviceName;
            return this;
        }

        /**
         * @param serviceName The target service name.
         * 
         * @return builder
         * 
         */
        public Builder serviceName(String serviceName) {
            return serviceName(Output.of(serviceName));
        }

        public GetLimitValuesArgs build() {
            $.compartmentId = Objects.requireNonNull($.compartmentId, "expected parameter 'compartmentId' to be non-null");
            $.serviceName = Objects.requireNonNull($.serviceName, "expected parameter 'serviceName' to be non-null");
            return $;
        }
    }

}