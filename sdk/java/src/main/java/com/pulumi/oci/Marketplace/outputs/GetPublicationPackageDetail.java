// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Marketplace.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Marketplace.outputs.GetPublicationPackageDetailEula;
import com.pulumi.oci.Marketplace.outputs.GetPublicationPackageDetailOperatingSystem;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetPublicationPackageDetail {
    private List<GetPublicationPackageDetailEula> eulas;
    private String imageId;
    private List<GetPublicationPackageDetailOperatingSystem> operatingSystems;
    /**
     * @return The listing&#39;s package type.
     * 
     */
    private String packageType;
    private String packageVersion;

    private GetPublicationPackageDetail() {}
    public List<GetPublicationPackageDetailEula> eulas() {
        return this.eulas;
    }
    public String imageId() {
        return this.imageId;
    }
    public List<GetPublicationPackageDetailOperatingSystem> operatingSystems() {
        return this.operatingSystems;
    }
    /**
     * @return The listing&#39;s package type.
     * 
     */
    public String packageType() {
        return this.packageType;
    }
    public String packageVersion() {
        return this.packageVersion;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetPublicationPackageDetail defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetPublicationPackageDetailEula> eulas;
        private String imageId;
        private List<GetPublicationPackageDetailOperatingSystem> operatingSystems;
        private String packageType;
        private String packageVersion;
        public Builder() {}
        public Builder(GetPublicationPackageDetail defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.eulas = defaults.eulas;
    	      this.imageId = defaults.imageId;
    	      this.operatingSystems = defaults.operatingSystems;
    	      this.packageType = defaults.packageType;
    	      this.packageVersion = defaults.packageVersion;
        }

        @CustomType.Setter
        public Builder eulas(List<GetPublicationPackageDetailEula> eulas) {
            this.eulas = Objects.requireNonNull(eulas);
            return this;
        }
        public Builder eulas(GetPublicationPackageDetailEula... eulas) {
            return eulas(List.of(eulas));
        }
        @CustomType.Setter
        public Builder imageId(String imageId) {
            this.imageId = Objects.requireNonNull(imageId);
            return this;
        }
        @CustomType.Setter
        public Builder operatingSystems(List<GetPublicationPackageDetailOperatingSystem> operatingSystems) {
            this.operatingSystems = Objects.requireNonNull(operatingSystems);
            return this;
        }
        public Builder operatingSystems(GetPublicationPackageDetailOperatingSystem... operatingSystems) {
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
        public GetPublicationPackageDetail build() {
            final var o = new GetPublicationPackageDetail();
            o.eulas = eulas;
            o.imageId = imageId;
            o.operatingSystems = operatingSystems;
            o.packageType = packageType;
            o.packageVersion = packageVersion;
            return o;
        }
    }
}