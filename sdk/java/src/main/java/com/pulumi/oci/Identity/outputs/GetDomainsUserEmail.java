// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Boolean;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetDomainsUserEmail {
    /**
     * @return Pending e-mail address verification
     * 
     */
    private String pendingVerificationData;
    /**
     * @return A Boolean value indicating the &#39;primary&#39; or preferred attribute value for this attribute. The primary attribute value &#39;true&#39; MUST appear no more than once.
     * 
     */
    private Boolean primary;
    /**
     * @return A Boolean value that indicates whether the email address is the secondary email address. The secondary attribute value &#39;true&#39; MUST appear no more than once.
     * 
     */
    private Boolean secondary;
    /**
     * @return A label indicating the attribute&#39;s function.
     * 
     */
    private String type;
    /**
     * @return The value of a X509 certificate.
     * 
     */
    private String value;
    /**
     * @return A Boolean value that indicates if the phone number is verified.
     * 
     */
    private Boolean verified;

    private GetDomainsUserEmail() {}
    /**
     * @return Pending e-mail address verification
     * 
     */
    public String pendingVerificationData() {
        return this.pendingVerificationData;
    }
    /**
     * @return A Boolean value indicating the &#39;primary&#39; or preferred attribute value for this attribute. The primary attribute value &#39;true&#39; MUST appear no more than once.
     * 
     */
    public Boolean primary() {
        return this.primary;
    }
    /**
     * @return A Boolean value that indicates whether the email address is the secondary email address. The secondary attribute value &#39;true&#39; MUST appear no more than once.
     * 
     */
    public Boolean secondary() {
        return this.secondary;
    }
    /**
     * @return A label indicating the attribute&#39;s function.
     * 
     */
    public String type() {
        return this.type;
    }
    /**
     * @return The value of a X509 certificate.
     * 
     */
    public String value() {
        return this.value;
    }
    /**
     * @return A Boolean value that indicates if the phone number is verified.
     * 
     */
    public Boolean verified() {
        return this.verified;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDomainsUserEmail defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String pendingVerificationData;
        private Boolean primary;
        private Boolean secondary;
        private String type;
        private String value;
        private Boolean verified;
        public Builder() {}
        public Builder(GetDomainsUserEmail defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.pendingVerificationData = defaults.pendingVerificationData;
    	      this.primary = defaults.primary;
    	      this.secondary = defaults.secondary;
    	      this.type = defaults.type;
    	      this.value = defaults.value;
    	      this.verified = defaults.verified;
        }

        @CustomType.Setter
        public Builder pendingVerificationData(String pendingVerificationData) {
            if (pendingVerificationData == null) {
              throw new MissingRequiredPropertyException("GetDomainsUserEmail", "pendingVerificationData");
            }
            this.pendingVerificationData = pendingVerificationData;
            return this;
        }
        @CustomType.Setter
        public Builder primary(Boolean primary) {
            if (primary == null) {
              throw new MissingRequiredPropertyException("GetDomainsUserEmail", "primary");
            }
            this.primary = primary;
            return this;
        }
        @CustomType.Setter
        public Builder secondary(Boolean secondary) {
            if (secondary == null) {
              throw new MissingRequiredPropertyException("GetDomainsUserEmail", "secondary");
            }
            this.secondary = secondary;
            return this;
        }
        @CustomType.Setter
        public Builder type(String type) {
            if (type == null) {
              throw new MissingRequiredPropertyException("GetDomainsUserEmail", "type");
            }
            this.type = type;
            return this;
        }
        @CustomType.Setter
        public Builder value(String value) {
            if (value == null) {
              throw new MissingRequiredPropertyException("GetDomainsUserEmail", "value");
            }
            this.value = value;
            return this;
        }
        @CustomType.Setter
        public Builder verified(Boolean verified) {
            if (verified == null) {
              throw new MissingRequiredPropertyException("GetDomainsUserEmail", "verified");
            }
            this.verified = verified;
            return this;
        }
        public GetDomainsUserEmail build() {
            final var _resultValue = new GetDomainsUserEmail();
            _resultValue.pendingVerificationData = pendingVerificationData;
            _resultValue.primary = primary;
            _resultValue.secondary = secondary;
            _resultValue.type = type;
            _resultValue.value = value;
            _resultValue.verified = verified;
            return _resultValue;
        }
    }
}
