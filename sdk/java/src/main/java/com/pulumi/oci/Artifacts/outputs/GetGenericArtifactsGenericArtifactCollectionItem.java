// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Artifacts.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetGenericArtifactsGenericArtifactCollectionItem {
    private String artifactId;
    /**
     * @return Filter results by a prefix for the `artifactPath` and and return artifacts that begin with the specified prefix in their path.
     * 
     */
    private String artifactPath;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    private String compartmentId;
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    private Map<String,String> definedTags;
    /**
     * @return A filter to return only resources that match the given display name exactly.
     * 
     */
    private String displayName;
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    private Map<String,String> freeformTags;
    /**
     * @return A filter to return the resources for the specified OCID.
     * 
     */
    private String id;
    /**
     * @return A filter to return the artifacts only for the specified repository OCID.
     * 
     */
    private String repositoryId;
    /**
     * @return Filter results by a specified SHA256 digest for the artifact.
     * 
     */
    private String sha256;
    /**
     * @return The size of the artifact in bytes.
     * 
     */
    private String sizeInBytes;
    /**
     * @return A filter to return only resources that match the given lifecycle state name exactly.
     * 
     */
    private String state;
    /**
     * @return An RFC 3339 timestamp indicating when the repository was created.
     * 
     */
    private String timeCreated;
    /**
     * @return Filter results by a prefix for `version` and return artifacts that that begin with the specified prefix in their version.
     * 
     */
    private String version;

    private GetGenericArtifactsGenericArtifactCollectionItem() {}
    public String artifactId() {
        return this.artifactId;
    }
    /**
     * @return Filter results by a prefix for the `artifactPath` and and return artifacts that begin with the specified prefix in their path.
     * 
     */
    public String artifactPath() {
        return this.artifactPath;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Map<String,String> definedTags() {
        return this.definedTags;
    }
    /**
     * @return A filter to return only resources that match the given display name exactly.
     * 
     */
    public String displayName() {
        return this.displayName;
    }
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Map<String,String> freeformTags() {
        return this.freeformTags;
    }
    /**
     * @return A filter to return the resources for the specified OCID.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return A filter to return the artifacts only for the specified repository OCID.
     * 
     */
    public String repositoryId() {
        return this.repositoryId;
    }
    /**
     * @return Filter results by a specified SHA256 digest for the artifact.
     * 
     */
    public String sha256() {
        return this.sha256;
    }
    /**
     * @return The size of the artifact in bytes.
     * 
     */
    public String sizeInBytes() {
        return this.sizeInBytes;
    }
    /**
     * @return A filter to return only resources that match the given lifecycle state name exactly.
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return An RFC 3339 timestamp indicating when the repository was created.
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return Filter results by a prefix for `version` and return artifacts that that begin with the specified prefix in their version.
     * 
     */
    public String version() {
        return this.version;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetGenericArtifactsGenericArtifactCollectionItem defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String artifactId;
        private String artifactPath;
        private String compartmentId;
        private Map<String,String> definedTags;
        private String displayName;
        private Map<String,String> freeformTags;
        private String id;
        private String repositoryId;
        private String sha256;
        private String sizeInBytes;
        private String state;
        private String timeCreated;
        private String version;
        public Builder() {}
        public Builder(GetGenericArtifactsGenericArtifactCollectionItem defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.artifactId = defaults.artifactId;
    	      this.artifactPath = defaults.artifactPath;
    	      this.compartmentId = defaults.compartmentId;
    	      this.definedTags = defaults.definedTags;
    	      this.displayName = defaults.displayName;
    	      this.freeformTags = defaults.freeformTags;
    	      this.id = defaults.id;
    	      this.repositoryId = defaults.repositoryId;
    	      this.sha256 = defaults.sha256;
    	      this.sizeInBytes = defaults.sizeInBytes;
    	      this.state = defaults.state;
    	      this.timeCreated = defaults.timeCreated;
    	      this.version = defaults.version;
        }

        @CustomType.Setter
        public Builder artifactId(String artifactId) {
            if (artifactId == null) {
              throw new MissingRequiredPropertyException("GetGenericArtifactsGenericArtifactCollectionItem", "artifactId");
            }
            this.artifactId = artifactId;
            return this;
        }
        @CustomType.Setter
        public Builder artifactPath(String artifactPath) {
            if (artifactPath == null) {
              throw new MissingRequiredPropertyException("GetGenericArtifactsGenericArtifactCollectionItem", "artifactPath");
            }
            this.artifactPath = artifactPath;
            return this;
        }
        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            if (compartmentId == null) {
              throw new MissingRequiredPropertyException("GetGenericArtifactsGenericArtifactCollectionItem", "compartmentId");
            }
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder definedTags(Map<String,String> definedTags) {
            if (definedTags == null) {
              throw new MissingRequiredPropertyException("GetGenericArtifactsGenericArtifactCollectionItem", "definedTags");
            }
            this.definedTags = definedTags;
            return this;
        }
        @CustomType.Setter
        public Builder displayName(String displayName) {
            if (displayName == null) {
              throw new MissingRequiredPropertyException("GetGenericArtifactsGenericArtifactCollectionItem", "displayName");
            }
            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder freeformTags(Map<String,String> freeformTags) {
            if (freeformTags == null) {
              throw new MissingRequiredPropertyException("GetGenericArtifactsGenericArtifactCollectionItem", "freeformTags");
            }
            this.freeformTags = freeformTags;
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetGenericArtifactsGenericArtifactCollectionItem", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder repositoryId(String repositoryId) {
            if (repositoryId == null) {
              throw new MissingRequiredPropertyException("GetGenericArtifactsGenericArtifactCollectionItem", "repositoryId");
            }
            this.repositoryId = repositoryId;
            return this;
        }
        @CustomType.Setter
        public Builder sha256(String sha256) {
            if (sha256 == null) {
              throw new MissingRequiredPropertyException("GetGenericArtifactsGenericArtifactCollectionItem", "sha256");
            }
            this.sha256 = sha256;
            return this;
        }
        @CustomType.Setter
        public Builder sizeInBytes(String sizeInBytes) {
            if (sizeInBytes == null) {
              throw new MissingRequiredPropertyException("GetGenericArtifactsGenericArtifactCollectionItem", "sizeInBytes");
            }
            this.sizeInBytes = sizeInBytes;
            return this;
        }
        @CustomType.Setter
        public Builder state(String state) {
            if (state == null) {
              throw new MissingRequiredPropertyException("GetGenericArtifactsGenericArtifactCollectionItem", "state");
            }
            this.state = state;
            return this;
        }
        @CustomType.Setter
        public Builder timeCreated(String timeCreated) {
            if (timeCreated == null) {
              throw new MissingRequiredPropertyException("GetGenericArtifactsGenericArtifactCollectionItem", "timeCreated");
            }
            this.timeCreated = timeCreated;
            return this;
        }
        @CustomType.Setter
        public Builder version(String version) {
            if (version == null) {
              throw new MissingRequiredPropertyException("GetGenericArtifactsGenericArtifactCollectionItem", "version");
            }
            this.version = version;
            return this;
        }
        public GetGenericArtifactsGenericArtifactCollectionItem build() {
            final var _resultValue = new GetGenericArtifactsGenericArtifactCollectionItem();
            _resultValue.artifactId = artifactId;
            _resultValue.artifactPath = artifactPath;
            _resultValue.compartmentId = compartmentId;
            _resultValue.definedTags = definedTags;
            _resultValue.displayName = displayName;
            _resultValue.freeformTags = freeformTags;
            _resultValue.id = id;
            _resultValue.repositoryId = repositoryId;
            _resultValue.sha256 = sha256;
            _resultValue.sizeInBytes = sizeInBytes;
            _resultValue.state = state;
            _resultValue.timeCreated = timeCreated;
            _resultValue.version = version;
            return _resultValue;
        }
    }
}
