// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetDomainsUsersUserUrnietfparamsscimschemasoracleidcsextensionmfaUserDevice {
    /**
     * @return Authentication method.
     * 
     */
    private String authenticationMethod;
    /**
     * @return A human readable name, primarily used for display purposes.
     * 
     */
    private String display;
    /**
     * @return Device authentication factor status.
     * 
     */
    private String factorStatus;
    /**
     * @return Authentication Factor Type
     * 
     */
    private String factorType;
    /**
     * @return Last Sync time for device.
     * 
     */
    private String lastSyncTime;
    /**
     * @return User Token URI
     * 
     */
    private String ref;
    /**
     * @return A supplemental status indicating the reason why a user is disabled
     * 
     */
    private String status;
    /**
     * @return Third party factor vendor name.
     * 
     */
    private String thirdPartyVendorName;
    /**
     * @return The value of a X509 certificate.
     * 
     */
    private String value;

    private GetDomainsUsersUserUrnietfparamsscimschemasoracleidcsextensionmfaUserDevice() {}
    /**
     * @return Authentication method.
     * 
     */
    public String authenticationMethod() {
        return this.authenticationMethod;
    }
    /**
     * @return A human readable name, primarily used for display purposes.
     * 
     */
    public String display() {
        return this.display;
    }
    /**
     * @return Device authentication factor status.
     * 
     */
    public String factorStatus() {
        return this.factorStatus;
    }
    /**
     * @return Authentication Factor Type
     * 
     */
    public String factorType() {
        return this.factorType;
    }
    /**
     * @return Last Sync time for device.
     * 
     */
    public String lastSyncTime() {
        return this.lastSyncTime;
    }
    /**
     * @return User Token URI
     * 
     */
    public String ref() {
        return this.ref;
    }
    /**
     * @return A supplemental status indicating the reason why a user is disabled
     * 
     */
    public String status() {
        return this.status;
    }
    /**
     * @return Third party factor vendor name.
     * 
     */
    public String thirdPartyVendorName() {
        return this.thirdPartyVendorName;
    }
    /**
     * @return The value of a X509 certificate.
     * 
     */
    public String value() {
        return this.value;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDomainsUsersUserUrnietfparamsscimschemasoracleidcsextensionmfaUserDevice defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String authenticationMethod;
        private String display;
        private String factorStatus;
        private String factorType;
        private String lastSyncTime;
        private String ref;
        private String status;
        private String thirdPartyVendorName;
        private String value;
        public Builder() {}
        public Builder(GetDomainsUsersUserUrnietfparamsscimschemasoracleidcsextensionmfaUserDevice defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.authenticationMethod = defaults.authenticationMethod;
    	      this.display = defaults.display;
    	      this.factorStatus = defaults.factorStatus;
    	      this.factorType = defaults.factorType;
    	      this.lastSyncTime = defaults.lastSyncTime;
    	      this.ref = defaults.ref;
    	      this.status = defaults.status;
    	      this.thirdPartyVendorName = defaults.thirdPartyVendorName;
    	      this.value = defaults.value;
        }

        @CustomType.Setter
        public Builder authenticationMethod(String authenticationMethod) {
            this.authenticationMethod = Objects.requireNonNull(authenticationMethod);
            return this;
        }
        @CustomType.Setter
        public Builder display(String display) {
            this.display = Objects.requireNonNull(display);
            return this;
        }
        @CustomType.Setter
        public Builder factorStatus(String factorStatus) {
            this.factorStatus = Objects.requireNonNull(factorStatus);
            return this;
        }
        @CustomType.Setter
        public Builder factorType(String factorType) {
            this.factorType = Objects.requireNonNull(factorType);
            return this;
        }
        @CustomType.Setter
        public Builder lastSyncTime(String lastSyncTime) {
            this.lastSyncTime = Objects.requireNonNull(lastSyncTime);
            return this;
        }
        @CustomType.Setter
        public Builder ref(String ref) {
            this.ref = Objects.requireNonNull(ref);
            return this;
        }
        @CustomType.Setter
        public Builder status(String status) {
            this.status = Objects.requireNonNull(status);
            return this;
        }
        @CustomType.Setter
        public Builder thirdPartyVendorName(String thirdPartyVendorName) {
            this.thirdPartyVendorName = Objects.requireNonNull(thirdPartyVendorName);
            return this;
        }
        @CustomType.Setter
        public Builder value(String value) {
            this.value = Objects.requireNonNull(value);
            return this;
        }
        public GetDomainsUsersUserUrnietfparamsscimschemasoracleidcsextensionmfaUserDevice build() {
            final var o = new GetDomainsUsersUserUrnietfparamsscimschemasoracleidcsextensionmfaUserDevice();
            o.authenticationMethod = authenticationMethod;
            o.display = display;
            o.factorStatus = factorStatus;
            o.factorType = factorType;
            o.lastSyncTime = lastSyncTime;
            o.ref = ref;
            o.status = status;
            o.thirdPartyVendorName = thirdPartyVendorName;
            o.value = value;
            return o;
        }
    }
}