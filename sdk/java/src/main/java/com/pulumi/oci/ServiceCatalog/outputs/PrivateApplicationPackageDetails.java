// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ServiceCatalog.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class PrivateApplicationPackageDetails {
    /**
     * @return The package&#39;s type.
     * 
     */
    private String packageType;
    /**
     * @return The package version.
     * 
     */
    private String version;
    private @Nullable String zipFileBase64encoded;

    private PrivateApplicationPackageDetails() {}
    /**
     * @return The package&#39;s type.
     * 
     */
    public String packageType() {
        return this.packageType;
    }
    /**
     * @return The package version.
     * 
     */
    public String version() {
        return this.version;
    }
    public Optional<String> zipFileBase64encoded() {
        return Optional.ofNullable(this.zipFileBase64encoded);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(PrivateApplicationPackageDetails defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String packageType;
        private String version;
        private @Nullable String zipFileBase64encoded;
        public Builder() {}
        public Builder(PrivateApplicationPackageDetails defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.packageType = defaults.packageType;
    	      this.version = defaults.version;
    	      this.zipFileBase64encoded = defaults.zipFileBase64encoded;
        }

        @CustomType.Setter
        public Builder packageType(String packageType) {
            if (packageType == null) {
              throw new MissingRequiredPropertyException("PrivateApplicationPackageDetails", "packageType");
            }
            this.packageType = packageType;
            return this;
        }
        @CustomType.Setter
        public Builder version(String version) {
            if (version == null) {
              throw new MissingRequiredPropertyException("PrivateApplicationPackageDetails", "version");
            }
            this.version = version;
            return this;
        }
        @CustomType.Setter
        public Builder zipFileBase64encoded(@Nullable String zipFileBase64encoded) {

            this.zipFileBase64encoded = zipFileBase64encoded;
            return this;
        }
        public PrivateApplicationPackageDetails build() {
            final var _resultValue = new PrivateApplicationPackageDetails();
            _resultValue.packageType = packageType;
            _resultValue.version = version;
            _resultValue.zipFileBase64encoded = zipFileBase64encoded;
            return _resultValue;
        }
    }
}
