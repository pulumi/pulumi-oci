// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Marketplace.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.oci.Marketplace.inputs.GetAcceptedAgreementsFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetAcceptedAgreementsPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetAcceptedAgreementsPlainArgs Empty = new GetAcceptedAgreementsPlainArgs();

    /**
     * The unique identifier for the accepted terms of use agreement.
     * 
     */
    @Import(name="acceptedAgreementId")
    private @Nullable String acceptedAgreementId;

    /**
     * @return The unique identifier for the accepted terms of use agreement.
     * 
     */
    public Optional<String> acceptedAgreementId() {
        return Optional.ofNullable(this.acceptedAgreementId);
    }

    /**
     * The unique identifier for the compartment.
     * 
     */
    @Import(name="compartmentId", required=true)
    private String compartmentId;

    /**
     * @return The unique identifier for the compartment.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }

    /**
     * The display name of the resource.
     * 
     */
    @Import(name="displayName")
    private @Nullable String displayName;

    /**
     * @return The display name of the resource.
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    @Import(name="filters")
    private @Nullable List<GetAcceptedAgreementsFilter> filters;

    public Optional<List<GetAcceptedAgreementsFilter>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * The unique identifier for the listing.
     * 
     */
    @Import(name="listingId")
    private @Nullable String listingId;

    /**
     * @return The unique identifier for the listing.
     * 
     */
    public Optional<String> listingId() {
        return Optional.ofNullable(this.listingId);
    }

    /**
     * The version of the package. Package versions are unique within a listing.
     * 
     */
    @Import(name="packageVersion")
    private @Nullable String packageVersion;

    /**
     * @return The version of the package. Package versions are unique within a listing.
     * 
     */
    public Optional<String> packageVersion() {
        return Optional.ofNullable(this.packageVersion);
    }

    private GetAcceptedAgreementsPlainArgs() {}

    private GetAcceptedAgreementsPlainArgs(GetAcceptedAgreementsPlainArgs $) {
        this.acceptedAgreementId = $.acceptedAgreementId;
        this.compartmentId = $.compartmentId;
        this.displayName = $.displayName;
        this.filters = $.filters;
        this.listingId = $.listingId;
        this.packageVersion = $.packageVersion;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetAcceptedAgreementsPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetAcceptedAgreementsPlainArgs $;

        public Builder() {
            $ = new GetAcceptedAgreementsPlainArgs();
        }

        public Builder(GetAcceptedAgreementsPlainArgs defaults) {
            $ = new GetAcceptedAgreementsPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param acceptedAgreementId The unique identifier for the accepted terms of use agreement.
         * 
         * @return builder
         * 
         */
        public Builder acceptedAgreementId(@Nullable String acceptedAgreementId) {
            $.acceptedAgreementId = acceptedAgreementId;
            return this;
        }

        /**
         * @param compartmentId The unique identifier for the compartment.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param displayName The display name of the resource.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable String displayName) {
            $.displayName = displayName;
            return this;
        }

        public Builder filters(@Nullable List<GetAcceptedAgreementsFilter> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(GetAcceptedAgreementsFilter... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param listingId The unique identifier for the listing.
         * 
         * @return builder
         * 
         */
        public Builder listingId(@Nullable String listingId) {
            $.listingId = listingId;
            return this;
        }

        /**
         * @param packageVersion The version of the package. Package versions are unique within a listing.
         * 
         * @return builder
         * 
         */
        public Builder packageVersion(@Nullable String packageVersion) {
            $.packageVersion = packageVersion;
            return this;
        }

        public GetAcceptedAgreementsPlainArgs build() {
            $.compartmentId = Objects.requireNonNull($.compartmentId, "expected parameter 'compartmentId' to be non-null");
            return $;
        }
    }

}