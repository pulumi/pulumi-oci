// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ApmSynthetics.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.ApmSynthetics.inputs.GetVantagePointsFilterArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetVantagePointsArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetVantagePointsArgs Empty = new GetVantagePointsArgs();

    /**
     * The APM domain ID the request is intended for.
     * 
     */
    @Import(name="apmDomainId", required=true)
    private Output<String> apmDomainId;

    /**
     * @return The APM domain ID the request is intended for.
     * 
     */
    public Output<String> apmDomainId() {
        return this.apmDomainId;
    }

    /**
     * A filter to return only the resources that match the entire display name.
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return A filter to return only the resources that match the entire display name.
     * 
     */
    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    @Import(name="filters")
    private @Nullable Output<List<GetVantagePointsFilterArgs>> filters;

    public Optional<Output<List<GetVantagePointsFilterArgs>>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * A filter to return only the resources that match the entire name.
     * 
     */
    @Import(name="name")
    private @Nullable Output<String> name;

    /**
     * @return A filter to return only the resources that match the entire name.
     * 
     */
    public Optional<Output<String>> name() {
        return Optional.ofNullable(this.name);
    }

    private GetVantagePointsArgs() {}

    private GetVantagePointsArgs(GetVantagePointsArgs $) {
        this.apmDomainId = $.apmDomainId;
        this.displayName = $.displayName;
        this.filters = $.filters;
        this.name = $.name;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetVantagePointsArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetVantagePointsArgs $;

        public Builder() {
            $ = new GetVantagePointsArgs();
        }

        public Builder(GetVantagePointsArgs defaults) {
            $ = new GetVantagePointsArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param apmDomainId The APM domain ID the request is intended for.
         * 
         * @return builder
         * 
         */
        public Builder apmDomainId(Output<String> apmDomainId) {
            $.apmDomainId = apmDomainId;
            return this;
        }

        /**
         * @param apmDomainId The APM domain ID the request is intended for.
         * 
         * @return builder
         * 
         */
        public Builder apmDomainId(String apmDomainId) {
            return apmDomainId(Output.of(apmDomainId));
        }

        /**
         * @param displayName A filter to return only the resources that match the entire display name.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName A filter to return only the resources that match the entire display name.
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        public Builder filters(@Nullable Output<List<GetVantagePointsFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(List<GetVantagePointsFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        public Builder filters(GetVantagePointsFilterArgs... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param name A filter to return only the resources that match the entire name.
         * 
         * @return builder
         * 
         */
        public Builder name(@Nullable Output<String> name) {
            $.name = name;
            return this;
        }

        /**
         * @param name A filter to return only the resources that match the entire name.
         * 
         * @return builder
         * 
         */
        public Builder name(String name) {
            return name(Output.of(name));
        }

        public GetVantagePointsArgs build() {
            $.apmDomainId = Objects.requireNonNull($.apmDomainId, "expected parameter 'apmDomainId' to be non-null");
            return $;
        }
    }

}