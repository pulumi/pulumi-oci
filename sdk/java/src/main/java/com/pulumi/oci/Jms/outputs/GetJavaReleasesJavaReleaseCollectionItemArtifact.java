// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Jms.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetJavaReleasesJavaReleaseCollectionItemArtifact {
    /**
     * @return Approximate compressed file size in bytes.
     * 
     */
    private String approximateFileSizeInBytes;
    /**
     * @return Product content type of this artifact.
     * 
     */
    private String artifactContentType;
    /**
     * @return Description of the binary artifact. Typically includes the OS, architecture, and installer type.
     * 
     */
    private String artifactDescription;
    /**
     * @return Unique identifier for the artifact.
     * 
     */
    private String artifactId;
    /**
     * @return SHA256 checksum of the artifact.
     * 
     */
    private String sha256;

    private GetJavaReleasesJavaReleaseCollectionItemArtifact() {}
    /**
     * @return Approximate compressed file size in bytes.
     * 
     */
    public String approximateFileSizeInBytes() {
        return this.approximateFileSizeInBytes;
    }
    /**
     * @return Product content type of this artifact.
     * 
     */
    public String artifactContentType() {
        return this.artifactContentType;
    }
    /**
     * @return Description of the binary artifact. Typically includes the OS, architecture, and installer type.
     * 
     */
    public String artifactDescription() {
        return this.artifactDescription;
    }
    /**
     * @return Unique identifier for the artifact.
     * 
     */
    public String artifactId() {
        return this.artifactId;
    }
    /**
     * @return SHA256 checksum of the artifact.
     * 
     */
    public String sha256() {
        return this.sha256;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetJavaReleasesJavaReleaseCollectionItemArtifact defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String approximateFileSizeInBytes;
        private String artifactContentType;
        private String artifactDescription;
        private String artifactId;
        private String sha256;
        public Builder() {}
        public Builder(GetJavaReleasesJavaReleaseCollectionItemArtifact defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.approximateFileSizeInBytes = defaults.approximateFileSizeInBytes;
    	      this.artifactContentType = defaults.artifactContentType;
    	      this.artifactDescription = defaults.artifactDescription;
    	      this.artifactId = defaults.artifactId;
    	      this.sha256 = defaults.sha256;
        }

        @CustomType.Setter
        public Builder approximateFileSizeInBytes(String approximateFileSizeInBytes) {
            this.approximateFileSizeInBytes = Objects.requireNonNull(approximateFileSizeInBytes);
            return this;
        }
        @CustomType.Setter
        public Builder artifactContentType(String artifactContentType) {
            this.artifactContentType = Objects.requireNonNull(artifactContentType);
            return this;
        }
        @CustomType.Setter
        public Builder artifactDescription(String artifactDescription) {
            this.artifactDescription = Objects.requireNonNull(artifactDescription);
            return this;
        }
        @CustomType.Setter
        public Builder artifactId(String artifactId) {
            this.artifactId = Objects.requireNonNull(artifactId);
            return this;
        }
        @CustomType.Setter
        public Builder sha256(String sha256) {
            this.sha256 = Objects.requireNonNull(sha256);
            return this;
        }
        public GetJavaReleasesJavaReleaseCollectionItemArtifact build() {
            final var o = new GetJavaReleasesJavaReleaseCollectionItemArtifact();
            o.approximateFileSizeInBytes = approximateFileSizeInBytes;
            o.artifactContentType = artifactContentType;
            o.artifactDescription = artifactDescription;
            o.artifactId = artifactId;
            o.sha256 = sha256;
            return o;
        }
    }
}