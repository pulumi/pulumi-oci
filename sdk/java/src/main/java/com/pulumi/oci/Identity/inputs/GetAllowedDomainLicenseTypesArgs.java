// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.Identity.inputs.GetAllowedDomainLicenseTypesFilterArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetAllowedDomainLicenseTypesArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetAllowedDomainLicenseTypesArgs Empty = new GetAllowedDomainLicenseTypesArgs();

    /**
     * The domain license type
     * 
     */
    @Import(name="currentLicenseTypeName")
    private @Nullable Output<String> currentLicenseTypeName;

    /**
     * @return The domain license type
     * 
     */
    public Optional<Output<String>> currentLicenseTypeName() {
        return Optional.ofNullable(this.currentLicenseTypeName);
    }

    @Import(name="filters")
    private @Nullable Output<List<GetAllowedDomainLicenseTypesFilterArgs>> filters;

    public Optional<Output<List<GetAllowedDomainLicenseTypesFilterArgs>>> filters() {
        return Optional.ofNullable(this.filters);
    }

    private GetAllowedDomainLicenseTypesArgs() {}

    private GetAllowedDomainLicenseTypesArgs(GetAllowedDomainLicenseTypesArgs $) {
        this.currentLicenseTypeName = $.currentLicenseTypeName;
        this.filters = $.filters;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetAllowedDomainLicenseTypesArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetAllowedDomainLicenseTypesArgs $;

        public Builder() {
            $ = new GetAllowedDomainLicenseTypesArgs();
        }

        public Builder(GetAllowedDomainLicenseTypesArgs defaults) {
            $ = new GetAllowedDomainLicenseTypesArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param currentLicenseTypeName The domain license type
         * 
         * @return builder
         * 
         */
        public Builder currentLicenseTypeName(@Nullable Output<String> currentLicenseTypeName) {
            $.currentLicenseTypeName = currentLicenseTypeName;
            return this;
        }

        /**
         * @param currentLicenseTypeName The domain license type
         * 
         * @return builder
         * 
         */
        public Builder currentLicenseTypeName(String currentLicenseTypeName) {
            return currentLicenseTypeName(Output.of(currentLicenseTypeName));
        }

        public Builder filters(@Nullable Output<List<GetAllowedDomainLicenseTypesFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(List<GetAllowedDomainLicenseTypesFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        public Builder filters(GetAllowedDomainLicenseTypesFilterArgs... filters) {
            return filters(List.of(filters));
        }

        public GetAllowedDomainLicenseTypesArgs build() {
            return $;
        }
    }

}