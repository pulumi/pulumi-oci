// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.HealthChecks.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Double;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetVantagePointsHealthChecksVantagePointGeo {
    /**
     * @return The ISO 3166-2 code for this location&#39;s first-level administrative division, either a US state or Canadian province. Only included for locations in the US or Canada. For a list of codes, see [Country Codes](https://www.iso.org/obp/ui/#search).
     * 
     */
    private String adminDivCode;
    /**
     * @return Common English-language name for the city.
     * 
     */
    private String cityName;
    /**
     * @return The ISO 3166-1 alpha-2 country code. For a list of codes, see [Country Codes](https://www.iso.org/obp/ui/#search).
     * 
     */
    private String countryCode;
    /**
     * @return The common English-language name for the country.
     * 
     */
    private String countryName;
    /**
     * @return An opaque identifier for the geographic location of the vantage point.
     * 
     */
    private String geoKey;
    /**
     * @return Degrees north of the Equator.
     * 
     */
    private Double latitude;
    /**
     * @return Degrees east of the prime meridian.
     * 
     */
    private Double longitude;

    private GetVantagePointsHealthChecksVantagePointGeo() {}
    /**
     * @return The ISO 3166-2 code for this location&#39;s first-level administrative division, either a US state or Canadian province. Only included for locations in the US or Canada. For a list of codes, see [Country Codes](https://www.iso.org/obp/ui/#search).
     * 
     */
    public String adminDivCode() {
        return this.adminDivCode;
    }
    /**
     * @return Common English-language name for the city.
     * 
     */
    public String cityName() {
        return this.cityName;
    }
    /**
     * @return The ISO 3166-1 alpha-2 country code. For a list of codes, see [Country Codes](https://www.iso.org/obp/ui/#search).
     * 
     */
    public String countryCode() {
        return this.countryCode;
    }
    /**
     * @return The common English-language name for the country.
     * 
     */
    public String countryName() {
        return this.countryName;
    }
    /**
     * @return An opaque identifier for the geographic location of the vantage point.
     * 
     */
    public String geoKey() {
        return this.geoKey;
    }
    /**
     * @return Degrees north of the Equator.
     * 
     */
    public Double latitude() {
        return this.latitude;
    }
    /**
     * @return Degrees east of the prime meridian.
     * 
     */
    public Double longitude() {
        return this.longitude;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetVantagePointsHealthChecksVantagePointGeo defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String adminDivCode;
        private String cityName;
        private String countryCode;
        private String countryName;
        private String geoKey;
        private Double latitude;
        private Double longitude;
        public Builder() {}
        public Builder(GetVantagePointsHealthChecksVantagePointGeo defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.adminDivCode = defaults.adminDivCode;
    	      this.cityName = defaults.cityName;
    	      this.countryCode = defaults.countryCode;
    	      this.countryName = defaults.countryName;
    	      this.geoKey = defaults.geoKey;
    	      this.latitude = defaults.latitude;
    	      this.longitude = defaults.longitude;
        }

        @CustomType.Setter
        public Builder adminDivCode(String adminDivCode) {
            this.adminDivCode = Objects.requireNonNull(adminDivCode);
            return this;
        }
        @CustomType.Setter
        public Builder cityName(String cityName) {
            this.cityName = Objects.requireNonNull(cityName);
            return this;
        }
        @CustomType.Setter
        public Builder countryCode(String countryCode) {
            this.countryCode = Objects.requireNonNull(countryCode);
            return this;
        }
        @CustomType.Setter
        public Builder countryName(String countryName) {
            this.countryName = Objects.requireNonNull(countryName);
            return this;
        }
        @CustomType.Setter
        public Builder geoKey(String geoKey) {
            this.geoKey = Objects.requireNonNull(geoKey);
            return this;
        }
        @CustomType.Setter
        public Builder latitude(Double latitude) {
            this.latitude = Objects.requireNonNull(latitude);
            return this;
        }
        @CustomType.Setter
        public Builder longitude(Double longitude) {
            this.longitude = Objects.requireNonNull(longitude);
            return this;
        }
        public GetVantagePointsHealthChecksVantagePointGeo build() {
            final var o = new GetVantagePointsHealthChecksVantagePointGeo();
            o.adminDivCode = adminDivCode;
            o.cityName = cityName;
            o.countryCode = countryCode;
            o.countryName = countryName;
            o.geoKey = geoKey;
            o.latitude = latitude;
            o.longitude = longitude;
            return o;
        }
    }
}