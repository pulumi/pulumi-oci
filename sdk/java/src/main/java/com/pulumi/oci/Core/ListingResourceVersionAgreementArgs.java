// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class ListingResourceVersionAgreementArgs extends com.pulumi.resources.ResourceArgs {

    public static final ListingResourceVersionAgreementArgs Empty = new ListingResourceVersionAgreementArgs();

    /**
     * The OCID of the listing.
     * 
     */
    @Import(name="listingId", required=true)
    private Output<String> listingId;

    /**
     * @return The OCID of the listing.
     * 
     */
    public Output<String> listingId() {
        return this.listingId;
    }

    /**
     * Listing Resource Version.
     * 
     */
    @Import(name="listingResourceVersion", required=true)
    private Output<String> listingResourceVersion;

    /**
     * @return Listing Resource Version.
     * 
     */
    public Output<String> listingResourceVersion() {
        return this.listingResourceVersion;
    }

    private ListingResourceVersionAgreementArgs() {}

    private ListingResourceVersionAgreementArgs(ListingResourceVersionAgreementArgs $) {
        this.listingId = $.listingId;
        this.listingResourceVersion = $.listingResourceVersion;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(ListingResourceVersionAgreementArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private ListingResourceVersionAgreementArgs $;

        public Builder() {
            $ = new ListingResourceVersionAgreementArgs();
        }

        public Builder(ListingResourceVersionAgreementArgs defaults) {
            $ = new ListingResourceVersionAgreementArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param listingId The OCID of the listing.
         * 
         * @return builder
         * 
         */
        public Builder listingId(Output<String> listingId) {
            $.listingId = listingId;
            return this;
        }

        /**
         * @param listingId The OCID of the listing.
         * 
         * @return builder
         * 
         */
        public Builder listingId(String listingId) {
            return listingId(Output.of(listingId));
        }

        /**
         * @param listingResourceVersion Listing Resource Version.
         * 
         * @return builder
         * 
         */
        public Builder listingResourceVersion(Output<String> listingResourceVersion) {
            $.listingResourceVersion = listingResourceVersion;
            return this;
        }

        /**
         * @param listingResourceVersion Listing Resource Version.
         * 
         * @return builder
         * 
         */
        public Builder listingResourceVersion(String listingResourceVersion) {
            return listingResourceVersion(Output.of(listingResourceVersion));
        }

        public ListingResourceVersionAgreementArgs build() {
            if ($.listingId == null) {
                throw new MissingRequiredPropertyException("ListingResourceVersionAgreementArgs", "listingId");
            }
            if ($.listingResourceVersion == null) {
                throw new MissingRequiredPropertyException("ListingResourceVersionAgreementArgs", "listingResourceVersion");
            }
            return $;
        }
    }

}
