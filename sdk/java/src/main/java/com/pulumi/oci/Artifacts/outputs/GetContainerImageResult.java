// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Artifacts.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Artifacts.outputs.GetContainerImageLayer;
import com.pulumi.oci.Artifacts.outputs.GetContainerImageVersion;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetContainerImageResult {
    /**
     * @return The compartment OCID to which the container image belongs. Inferred from the container repository.
     * 
     */
    private String compartmentId;
    /**
     * @return The OCID of the user or principal that pushed the version.
     * 
     */
    private String createdBy;
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    private Map<String,String> definedTags;
    /**
     * @return The sha256 digest of the image layer.
     * 
     */
    private String digest;
    /**
     * @return The repository name and the most recent version associated with the image. If there are no versions associated with the image, then last known version and digest are used instead. If the last known version is unavailable, then &#39;unknown&#39; is used instead of the version.  Example: `ubuntu:latest` or `ubuntu:latest{@literal @}sha256:45b23dee08af5e43a7fea6c4cf9c25ccf269ee113168c19722f87876677c5cb2`
     * 
     */
    private String displayName;
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    private Map<String,String> freeformTags;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    private String imageId;
    /**
     * @return Layers of which the image is composed, ordered by the layer digest.
     * 
     */
    private List<GetContainerImageLayer> layers;
    /**
     * @return The total size of the container image layers in bytes.
     * 
     */
    private String layersSizeInBytes;
    /**
     * @return The size of the container image manifest in bytes.
     * 
     */
    private Integer manifestSizeInBytes;
    /**
     * @return Total number of pulls.
     * 
     */
    private String pullCount;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the container repository.
     * 
     */
    private String repositoryId;
    /**
     * @return The container repository name.
     * 
     */
    private String repositoryName;
    /**
     * @return The current state of the container image.
     * 
     */
    private String state;
    /**
     * @return The system tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    private Map<String,String> systemTags;
    /**
     * @return The creation time of the version.
     * 
     */
    private String timeCreated;
    /**
     * @return An RFC 3339 timestamp indicating when the image was last pulled.
     * 
     */
    private String timeLastPulled;
    /**
     * @return The version name.
     * 
     */
    private String version;
    /**
     * @return The versions associated with this image.
     * 
     */
    private List<GetContainerImageVersion> versions;

    private GetContainerImageResult() {}
    /**
     * @return The compartment OCID to which the container image belongs. Inferred from the container repository.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return The OCID of the user or principal that pushed the version.
     * 
     */
    public String createdBy() {
        return this.createdBy;
    }
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Map<String,String> definedTags() {
        return this.definedTags;
    }
    /**
     * @return The sha256 digest of the image layer.
     * 
     */
    public String digest() {
        return this.digest;
    }
    /**
     * @return The repository name and the most recent version associated with the image. If there are no versions associated with the image, then last known version and digest are used instead. If the last known version is unavailable, then &#39;unknown&#39; is used instead of the version.  Example: `ubuntu:latest` or `ubuntu:latest{@literal @}sha256:45b23dee08af5e43a7fea6c4cf9c25ccf269ee113168c19722f87876677c5cb2`
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
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    public String imageId() {
        return this.imageId;
    }
    /**
     * @return Layers of which the image is composed, ordered by the layer digest.
     * 
     */
    public List<GetContainerImageLayer> layers() {
        return this.layers;
    }
    /**
     * @return The total size of the container image layers in bytes.
     * 
     */
    public String layersSizeInBytes() {
        return this.layersSizeInBytes;
    }
    /**
     * @return The size of the container image manifest in bytes.
     * 
     */
    public Integer manifestSizeInBytes() {
        return this.manifestSizeInBytes;
    }
    /**
     * @return Total number of pulls.
     * 
     */
    public String pullCount() {
        return this.pullCount;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the container repository.
     * 
     */
    public String repositoryId() {
        return this.repositoryId;
    }
    /**
     * @return The container repository name.
     * 
     */
    public String repositoryName() {
        return this.repositoryName;
    }
    /**
     * @return The current state of the container image.
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return The system tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    public Map<String,String> systemTags() {
        return this.systemTags;
    }
    /**
     * @return The creation time of the version.
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return An RFC 3339 timestamp indicating when the image was last pulled.
     * 
     */
    public String timeLastPulled() {
        return this.timeLastPulled;
    }
    /**
     * @return The version name.
     * 
     */
    public String version() {
        return this.version;
    }
    /**
     * @return The versions associated with this image.
     * 
     */
    public List<GetContainerImageVersion> versions() {
        return this.versions;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetContainerImageResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String compartmentId;
        private String createdBy;
        private Map<String,String> definedTags;
        private String digest;
        private String displayName;
        private Map<String,String> freeformTags;
        private String id;
        private String imageId;
        private List<GetContainerImageLayer> layers;
        private String layersSizeInBytes;
        private Integer manifestSizeInBytes;
        private String pullCount;
        private String repositoryId;
        private String repositoryName;
        private String state;
        private Map<String,String> systemTags;
        private String timeCreated;
        private String timeLastPulled;
        private String version;
        private List<GetContainerImageVersion> versions;
        public Builder() {}
        public Builder(GetContainerImageResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.createdBy = defaults.createdBy;
    	      this.definedTags = defaults.definedTags;
    	      this.digest = defaults.digest;
    	      this.displayName = defaults.displayName;
    	      this.freeformTags = defaults.freeformTags;
    	      this.id = defaults.id;
    	      this.imageId = defaults.imageId;
    	      this.layers = defaults.layers;
    	      this.layersSizeInBytes = defaults.layersSizeInBytes;
    	      this.manifestSizeInBytes = defaults.manifestSizeInBytes;
    	      this.pullCount = defaults.pullCount;
    	      this.repositoryId = defaults.repositoryId;
    	      this.repositoryName = defaults.repositoryName;
    	      this.state = defaults.state;
    	      this.systemTags = defaults.systemTags;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeLastPulled = defaults.timeLastPulled;
    	      this.version = defaults.version;
    	      this.versions = defaults.versions;
        }

        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            if (compartmentId == null) {
              throw new MissingRequiredPropertyException("GetContainerImageResult", "compartmentId");
            }
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder createdBy(String createdBy) {
            if (createdBy == null) {
              throw new MissingRequiredPropertyException("GetContainerImageResult", "createdBy");
            }
            this.createdBy = createdBy;
            return this;
        }
        @CustomType.Setter
        public Builder definedTags(Map<String,String> definedTags) {
            if (definedTags == null) {
              throw new MissingRequiredPropertyException("GetContainerImageResult", "definedTags");
            }
            this.definedTags = definedTags;
            return this;
        }
        @CustomType.Setter
        public Builder digest(String digest) {
            if (digest == null) {
              throw new MissingRequiredPropertyException("GetContainerImageResult", "digest");
            }
            this.digest = digest;
            return this;
        }
        @CustomType.Setter
        public Builder displayName(String displayName) {
            if (displayName == null) {
              throw new MissingRequiredPropertyException("GetContainerImageResult", "displayName");
            }
            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder freeformTags(Map<String,String> freeformTags) {
            if (freeformTags == null) {
              throw new MissingRequiredPropertyException("GetContainerImageResult", "freeformTags");
            }
            this.freeformTags = freeformTags;
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetContainerImageResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder imageId(String imageId) {
            if (imageId == null) {
              throw new MissingRequiredPropertyException("GetContainerImageResult", "imageId");
            }
            this.imageId = imageId;
            return this;
        }
        @CustomType.Setter
        public Builder layers(List<GetContainerImageLayer> layers) {
            if (layers == null) {
              throw new MissingRequiredPropertyException("GetContainerImageResult", "layers");
            }
            this.layers = layers;
            return this;
        }
        public Builder layers(GetContainerImageLayer... layers) {
            return layers(List.of(layers));
        }
        @CustomType.Setter
        public Builder layersSizeInBytes(String layersSizeInBytes) {
            if (layersSizeInBytes == null) {
              throw new MissingRequiredPropertyException("GetContainerImageResult", "layersSizeInBytes");
            }
            this.layersSizeInBytes = layersSizeInBytes;
            return this;
        }
        @CustomType.Setter
        public Builder manifestSizeInBytes(Integer manifestSizeInBytes) {
            if (manifestSizeInBytes == null) {
              throw new MissingRequiredPropertyException("GetContainerImageResult", "manifestSizeInBytes");
            }
            this.manifestSizeInBytes = manifestSizeInBytes;
            return this;
        }
        @CustomType.Setter
        public Builder pullCount(String pullCount) {
            if (pullCount == null) {
              throw new MissingRequiredPropertyException("GetContainerImageResult", "pullCount");
            }
            this.pullCount = pullCount;
            return this;
        }
        @CustomType.Setter
        public Builder repositoryId(String repositoryId) {
            if (repositoryId == null) {
              throw new MissingRequiredPropertyException("GetContainerImageResult", "repositoryId");
            }
            this.repositoryId = repositoryId;
            return this;
        }
        @CustomType.Setter
        public Builder repositoryName(String repositoryName) {
            if (repositoryName == null) {
              throw new MissingRequiredPropertyException("GetContainerImageResult", "repositoryName");
            }
            this.repositoryName = repositoryName;
            return this;
        }
        @CustomType.Setter
        public Builder state(String state) {
            if (state == null) {
              throw new MissingRequiredPropertyException("GetContainerImageResult", "state");
            }
            this.state = state;
            return this;
        }
        @CustomType.Setter
        public Builder systemTags(Map<String,String> systemTags) {
            if (systemTags == null) {
              throw new MissingRequiredPropertyException("GetContainerImageResult", "systemTags");
            }
            this.systemTags = systemTags;
            return this;
        }
        @CustomType.Setter
        public Builder timeCreated(String timeCreated) {
            if (timeCreated == null) {
              throw new MissingRequiredPropertyException("GetContainerImageResult", "timeCreated");
            }
            this.timeCreated = timeCreated;
            return this;
        }
        @CustomType.Setter
        public Builder timeLastPulled(String timeLastPulled) {
            if (timeLastPulled == null) {
              throw new MissingRequiredPropertyException("GetContainerImageResult", "timeLastPulled");
            }
            this.timeLastPulled = timeLastPulled;
            return this;
        }
        @CustomType.Setter
        public Builder version(String version) {
            if (version == null) {
              throw new MissingRequiredPropertyException("GetContainerImageResult", "version");
            }
            this.version = version;
            return this;
        }
        @CustomType.Setter
        public Builder versions(List<GetContainerImageVersion> versions) {
            if (versions == null) {
              throw new MissingRequiredPropertyException("GetContainerImageResult", "versions");
            }
            this.versions = versions;
            return this;
        }
        public Builder versions(GetContainerImageVersion... versions) {
            return versions(List.of(versions));
        }
        public GetContainerImageResult build() {
            final var _resultValue = new GetContainerImageResult();
            _resultValue.compartmentId = compartmentId;
            _resultValue.createdBy = createdBy;
            _resultValue.definedTags = definedTags;
            _resultValue.digest = digest;
            _resultValue.displayName = displayName;
            _resultValue.freeformTags = freeformTags;
            _resultValue.id = id;
            _resultValue.imageId = imageId;
            _resultValue.layers = layers;
            _resultValue.layersSizeInBytes = layersSizeInBytes;
            _resultValue.manifestSizeInBytes = manifestSizeInBytes;
            _resultValue.pullCount = pullCount;
            _resultValue.repositoryId = repositoryId;
            _resultValue.repositoryName = repositoryName;
            _resultValue.state = state;
            _resultValue.systemTags = systemTags;
            _resultValue.timeCreated = timeCreated;
            _resultValue.timeLastPulled = timeLastPulled;
            _resultValue.version = version;
            _resultValue.versions = versions;
            return _resultValue;
        }
    }
}
