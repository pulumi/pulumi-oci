// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Boolean;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetDomainsUsersUserAddress {
    /**
     * @return The country name component.
     * 
     */
    private String country;
    /**
     * @return Full name
     * 
     */
    private String formatted;
    /**
     * @return The city or locality component.
     * 
     */
    private String locality;
    /**
     * @return The zipcode or postal code component.
     * 
     */
    private String postalCode;
    /**
     * @return A Boolean value indicating the &#39;primary&#39; or preferred attribute value for this attribute. The primary attribute value &#39;true&#39; MUST appear no more than once.
     * 
     */
    private Boolean primary;
    /**
     * @return The state or region component.
     * 
     */
    private String region;
    /**
     * @return The full street address component, which may include house number, street name, PO BOX, and multi-line extended street address information. This attribute MAY contain newlines.
     * 
     */
    private String streetAddress;
    /**
     * @return A label indicating the attribute&#39;s function.
     * 
     */
    private String type;

    private GetDomainsUsersUserAddress() {}
    /**
     * @return The country name component.
     * 
     */
    public String country() {
        return this.country;
    }
    /**
     * @return Full name
     * 
     */
    public String formatted() {
        return this.formatted;
    }
    /**
     * @return The city or locality component.
     * 
     */
    public String locality() {
        return this.locality;
    }
    /**
     * @return The zipcode or postal code component.
     * 
     */
    public String postalCode() {
        return this.postalCode;
    }
    /**
     * @return A Boolean value indicating the &#39;primary&#39; or preferred attribute value for this attribute. The primary attribute value &#39;true&#39; MUST appear no more than once.
     * 
     */
    public Boolean primary() {
        return this.primary;
    }
    /**
     * @return The state or region component.
     * 
     */
    public String region() {
        return this.region;
    }
    /**
     * @return The full street address component, which may include house number, street name, PO BOX, and multi-line extended street address information. This attribute MAY contain newlines.
     * 
     */
    public String streetAddress() {
        return this.streetAddress;
    }
    /**
     * @return A label indicating the attribute&#39;s function.
     * 
     */
    public String type() {
        return this.type;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDomainsUsersUserAddress defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String country;
        private String formatted;
        private String locality;
        private String postalCode;
        private Boolean primary;
        private String region;
        private String streetAddress;
        private String type;
        public Builder() {}
        public Builder(GetDomainsUsersUserAddress defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.country = defaults.country;
    	      this.formatted = defaults.formatted;
    	      this.locality = defaults.locality;
    	      this.postalCode = defaults.postalCode;
    	      this.primary = defaults.primary;
    	      this.region = defaults.region;
    	      this.streetAddress = defaults.streetAddress;
    	      this.type = defaults.type;
        }

        @CustomType.Setter
        public Builder country(String country) {
            this.country = Objects.requireNonNull(country);
            return this;
        }
        @CustomType.Setter
        public Builder formatted(String formatted) {
            this.formatted = Objects.requireNonNull(formatted);
            return this;
        }
        @CustomType.Setter
        public Builder locality(String locality) {
            this.locality = Objects.requireNonNull(locality);
            return this;
        }
        @CustomType.Setter
        public Builder postalCode(String postalCode) {
            this.postalCode = Objects.requireNonNull(postalCode);
            return this;
        }
        @CustomType.Setter
        public Builder primary(Boolean primary) {
            this.primary = Objects.requireNonNull(primary);
            return this;
        }
        @CustomType.Setter
        public Builder region(String region) {
            this.region = Objects.requireNonNull(region);
            return this;
        }
        @CustomType.Setter
        public Builder streetAddress(String streetAddress) {
            this.streetAddress = Objects.requireNonNull(streetAddress);
            return this;
        }
        @CustomType.Setter
        public Builder type(String type) {
            this.type = Objects.requireNonNull(type);
            return this;
        }
        public GetDomainsUsersUserAddress build() {
            final var o = new GetDomainsUsersUserAddress();
            o.country = country;
            o.formatted = formatted;
            o.locality = locality;
            o.postalCode = postalCode;
            o.primary = primary;
            o.region = region;
            o.streetAddress = streetAddress;
            o.type = type;
            return o;
        }
    }
}