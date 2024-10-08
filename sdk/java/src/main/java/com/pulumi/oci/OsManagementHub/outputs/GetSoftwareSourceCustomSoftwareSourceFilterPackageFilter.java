// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.OsManagementHub.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetSoftwareSourceCustomSoftwareSourceFilterPackageFilter {
    /**
     * @return The type of the filter.
     * 
     */
    private String filterType;
    /**
     * @return The package name.
     * 
     */
    private String packageName;
    /**
     * @return The package name pattern.
     * 
     */
    private String packageNamePattern;
    /**
     * @return The package version, which is denoted by &#39;version-release&#39;, or &#39;epoch:version-release&#39;.
     * 
     */
    private String packageVersion;

    private GetSoftwareSourceCustomSoftwareSourceFilterPackageFilter() {}
    /**
     * @return The type of the filter.
     * 
     */
    public String filterType() {
        return this.filterType;
    }
    /**
     * @return The package name.
     * 
     */
    public String packageName() {
        return this.packageName;
    }
    /**
     * @return The package name pattern.
     * 
     */
    public String packageNamePattern() {
        return this.packageNamePattern;
    }
    /**
     * @return The package version, which is denoted by &#39;version-release&#39;, or &#39;epoch:version-release&#39;.
     * 
     */
    public String packageVersion() {
        return this.packageVersion;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetSoftwareSourceCustomSoftwareSourceFilterPackageFilter defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String filterType;
        private String packageName;
        private String packageNamePattern;
        private String packageVersion;
        public Builder() {}
        public Builder(GetSoftwareSourceCustomSoftwareSourceFilterPackageFilter defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.filterType = defaults.filterType;
    	      this.packageName = defaults.packageName;
    	      this.packageNamePattern = defaults.packageNamePattern;
    	      this.packageVersion = defaults.packageVersion;
        }

        @CustomType.Setter
        public Builder filterType(String filterType) {
            if (filterType == null) {
              throw new MissingRequiredPropertyException("GetSoftwareSourceCustomSoftwareSourceFilterPackageFilter", "filterType");
            }
            this.filterType = filterType;
            return this;
        }
        @CustomType.Setter
        public Builder packageName(String packageName) {
            if (packageName == null) {
              throw new MissingRequiredPropertyException("GetSoftwareSourceCustomSoftwareSourceFilterPackageFilter", "packageName");
            }
            this.packageName = packageName;
            return this;
        }
        @CustomType.Setter
        public Builder packageNamePattern(String packageNamePattern) {
            if (packageNamePattern == null) {
              throw new MissingRequiredPropertyException("GetSoftwareSourceCustomSoftwareSourceFilterPackageFilter", "packageNamePattern");
            }
            this.packageNamePattern = packageNamePattern;
            return this;
        }
        @CustomType.Setter
        public Builder packageVersion(String packageVersion) {
            if (packageVersion == null) {
              throw new MissingRequiredPropertyException("GetSoftwareSourceCustomSoftwareSourceFilterPackageFilter", "packageVersion");
            }
            this.packageVersion = packageVersion;
            return this;
        }
        public GetSoftwareSourceCustomSoftwareSourceFilterPackageFilter build() {
            final var _resultValue = new GetSoftwareSourceCustomSoftwareSourceFilterPackageFilter();
            _resultValue.filterType = filterType;
            _resultValue.packageName = packageName;
            _resultValue.packageNamePattern = packageNamePattern;
            _resultValue.packageVersion = packageVersion;
            return _resultValue;
        }
    }
}
