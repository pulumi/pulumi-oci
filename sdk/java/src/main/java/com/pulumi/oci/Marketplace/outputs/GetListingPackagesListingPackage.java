// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Marketplace.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Marketplace.outputs.GetListingPackagesListingPackageOperatingSystem;
import com.pulumi.oci.Marketplace.outputs.GetListingPackagesListingPackagePricing;
import com.pulumi.oci.Marketplace.outputs.GetListingPackagesListingPackageRegion;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetListingPackagesListingPackage {
    /**
     * @return The unique identifier for the listing.
     * 
     */
    private String listingId;
    /**
     * @return The operating system used by the listing.
     * 
     */
    private List<GetListingPackagesListingPackageOperatingSystem> operatingSystems;
    /**
     * @return A filter to return only packages that match the given package type exactly.
     * 
     */
    private String packageType;
    /**
     * @return The version of the package. Package versions are unique within a listing.
     * 
     */
    private String packageVersion;
    /**
     * @return The model for pricing.
     * 
     */
    private List<GetListingPackagesListingPackagePricing> pricings;
    /**
     * @return The regions where the listing is available.
     * 
     */
    private List<GetListingPackagesListingPackageRegion> regions;
    /**
     * @return The unique identifier for the package resource.
     * 
     */
    private String resourceId;
    /**
     * @return The date and time this listing package was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    private String timeCreated;

    private GetListingPackagesListingPackage() {}
    /**
     * @return The unique identifier for the listing.
     * 
     */
    public String listingId() {
        return this.listingId;
    }
    /**
     * @return The operating system used by the listing.
     * 
     */
    public List<GetListingPackagesListingPackageOperatingSystem> operatingSystems() {
        return this.operatingSystems;
    }
    /**
     * @return A filter to return only packages that match the given package type exactly.
     * 
     */
    public String packageType() {
        return this.packageType;
    }
    /**
     * @return The version of the package. Package versions are unique within a listing.
     * 
     */
    public String packageVersion() {
        return this.packageVersion;
    }
    /**
     * @return The model for pricing.
     * 
     */
    public List<GetListingPackagesListingPackagePricing> pricings() {
        return this.pricings;
    }
    /**
     * @return The regions where the listing is available.
     * 
     */
    public List<GetListingPackagesListingPackageRegion> regions() {
        return this.regions;
    }
    /**
     * @return The unique identifier for the package resource.
     * 
     */
    public String resourceId() {
        return this.resourceId;
    }
    /**
     * @return The date and time this listing package was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetListingPackagesListingPackage defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String listingId;
        private List<GetListingPackagesListingPackageOperatingSystem> operatingSystems;
        private String packageType;
        private String packageVersion;
        private List<GetListingPackagesListingPackagePricing> pricings;
        private List<GetListingPackagesListingPackageRegion> regions;
        private String resourceId;
        private String timeCreated;
        public Builder() {}
        public Builder(GetListingPackagesListingPackage defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.listingId = defaults.listingId;
    	      this.operatingSystems = defaults.operatingSystems;
    	      this.packageType = defaults.packageType;
    	      this.packageVersion = defaults.packageVersion;
    	      this.pricings = defaults.pricings;
    	      this.regions = defaults.regions;
    	      this.resourceId = defaults.resourceId;
    	      this.timeCreated = defaults.timeCreated;
        }

        @CustomType.Setter
        public Builder listingId(String listingId) {
            this.listingId = Objects.requireNonNull(listingId);
            return this;
        }
        @CustomType.Setter
        public Builder operatingSystems(List<GetListingPackagesListingPackageOperatingSystem> operatingSystems) {
            this.operatingSystems = Objects.requireNonNull(operatingSystems);
            return this;
        }
        public Builder operatingSystems(GetListingPackagesListingPackageOperatingSystem... operatingSystems) {
            return operatingSystems(List.of(operatingSystems));
        }
        @CustomType.Setter
        public Builder packageType(String packageType) {
            this.packageType = Objects.requireNonNull(packageType);
            return this;
        }
        @CustomType.Setter
        public Builder packageVersion(String packageVersion) {
            this.packageVersion = Objects.requireNonNull(packageVersion);
            return this;
        }
        @CustomType.Setter
        public Builder pricings(List<GetListingPackagesListingPackagePricing> pricings) {
            this.pricings = Objects.requireNonNull(pricings);
            return this;
        }
        public Builder pricings(GetListingPackagesListingPackagePricing... pricings) {
            return pricings(List.of(pricings));
        }
        @CustomType.Setter
        public Builder regions(List<GetListingPackagesListingPackageRegion> regions) {
            this.regions = Objects.requireNonNull(regions);
            return this;
        }
        public Builder regions(GetListingPackagesListingPackageRegion... regions) {
            return regions(List.of(regions));
        }
        @CustomType.Setter
        public Builder resourceId(String resourceId) {
            this.resourceId = Objects.requireNonNull(resourceId);
            return this;
        }
        @CustomType.Setter
        public Builder timeCreated(String timeCreated) {
            this.timeCreated = Objects.requireNonNull(timeCreated);
            return this;
        }
        public GetListingPackagesListingPackage build() {
            final var o = new GetListingPackagesListingPackage();
            o.listingId = listingId;
            o.operatingSystems = operatingSystems;
            o.packageType = packageType;
            o.packageVersion = packageVersion;
            o.pricings = pricings;
            o.regions = regions;
            o.resourceId = resourceId;
            o.timeCreated = timeCreated;
            return o;
        }
    }
}