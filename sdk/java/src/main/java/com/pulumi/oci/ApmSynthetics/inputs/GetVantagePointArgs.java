// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ApmSynthetics.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetVantagePointArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetVantagePointArgs Empty = new GetVantagePointArgs();

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

    private GetVantagePointArgs() {}

    private GetVantagePointArgs(GetVantagePointArgs $) {
        this.apmDomainId = $.apmDomainId;
        this.displayName = $.displayName;
        this.name = $.name;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetVantagePointArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetVantagePointArgs $;

        public Builder() {
            $ = new GetVantagePointArgs();
        }

        public Builder(GetVantagePointArgs defaults) {
            $ = new GetVantagePointArgs(Objects.requireNonNull(defaults));
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

        public GetVantagePointArgs build() {
            if ($.apmDomainId == null) {
                throw new MissingRequiredPropertyException("GetVantagePointArgs", "apmDomainId");
            }
            return $;
        }
    }

}
