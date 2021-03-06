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
    private final List<GetPublicationPackageDetailEula> eulas;
    private final String imageId;
    private final List<GetPublicationPackageDetailOperatingSystem> operatingSystems;
    /**
     * @return The listing&#39;s package type.
     * 
     */
    private final String packageType;
    private final String packageVersion;

    @CustomType.Constructor
    private GetPublicationPackageDetail(
        @CustomType.Parameter("eulas") List<GetPublicationPackageDetailEula> eulas,
        @CustomType.Parameter("imageId") String imageId,
        @CustomType.Parameter("operatingSystems") List<GetPublicationPackageDetailOperatingSystem> operatingSystems,
        @CustomType.Parameter("packageType") String packageType,
        @CustomType.Parameter("packageVersion") String packageVersion) {
        this.eulas = eulas;
        this.imageId = imageId;
        this.operatingSystems = operatingSystems;
        this.packageType = packageType;
        this.packageVersion = packageVersion;
    }

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

    public static final class Builder {
        private List<GetPublicationPackageDetailEula> eulas;
        private String imageId;
        private List<GetPublicationPackageDetailOperatingSystem> operatingSystems;
        private String packageType;
        private String packageVersion;

        public Builder() {
    	      // Empty
        }

        public Builder(GetPublicationPackageDetail defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.eulas = defaults.eulas;
    	      this.imageId = defaults.imageId;
    	      this.operatingSystems = defaults.operatingSystems;
    	      this.packageType = defaults.packageType;
    	      this.packageVersion = defaults.packageVersion;
        }

        public Builder eulas(List<GetPublicationPackageDetailEula> eulas) {
            this.eulas = Objects.requireNonNull(eulas);
            return this;
        }
        public Builder eulas(GetPublicationPackageDetailEula... eulas) {
            return eulas(List.of(eulas));
        }
        public Builder imageId(String imageId) {
            this.imageId = Objects.requireNonNull(imageId);
            return this;
        }
        public Builder operatingSystems(List<GetPublicationPackageDetailOperatingSystem> operatingSystems) {
            this.operatingSystems = Objects.requireNonNull(operatingSystems);
            return this;
        }
        public Builder operatingSystems(GetPublicationPackageDetailOperatingSystem... operatingSystems) {
            return operatingSystems(List.of(operatingSystems));
        }
        public Builder packageType(String packageType) {
            this.packageType = Objects.requireNonNull(packageType);
            return this;
        }
        public Builder packageVersion(String packageVersion) {
            this.packageVersion = Objects.requireNonNull(packageVersion);
            return this;
        }        public GetPublicationPackageDetail build() {
            return new GetPublicationPackageDetail(eulas, imageId, operatingSystems, packageType, packageVersion);
        }
    }
}
