// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.FileStorage.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Boolean;
import java.lang.Object;
import java.lang.String;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetSnapshotsSnapshot {
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    private final Map<String,Object> definedTags;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the file system.
     * 
     */
    private final String fileSystemId;
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    private final Map<String,Object> freeformTags;
    /**
     * @return Filter results by [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm). Must be an OCID of the correct type for the resouce type.
     * 
     */
    private final String id;
    /**
     * @return Specifies whether the snapshot has been cloned. See [Cloning a File System](https://docs.cloud.oracle.com/iaas/Content/File/Tasks/cloningafilesystem.htm).
     * 
     */
    private final Boolean isCloneSource;
    /**
     * @return Additional information about the current &#39;lifecycleState&#39;.
     * 
     */
    private final String lifecycleDetails;
    /**
     * @return Name of the snapshot. This value is immutable.
     * 
     */
    private final String name;
    /**
     * @return An [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) identifying the parent from which this snapshot was cloned. If this snapshot was not cloned, then the `provenanceId` is the same as the snapshot `id` value. If this snapshot was cloned, then the `provenanceId` value is the parent&#39;s `provenanceId`. See [Cloning a File System](https://docs.cloud.oracle.com/iaas/Content/File/Tasks/cloningafilesystem.htm).
     * 
     */
    private final String provenanceId;
    /**
     * @return Filter results by the specified lifecycle state. Must be a valid state for the resource type.
     * 
     */
    private final String state;
    /**
     * @return The date and time the snapshot was created, expressed in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) timestamp format.  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    private final String timeCreated;

    @CustomType.Constructor
    private GetSnapshotsSnapshot(
        @CustomType.Parameter("definedTags") Map<String,Object> definedTags,
        @CustomType.Parameter("fileSystemId") String fileSystemId,
        @CustomType.Parameter("freeformTags") Map<String,Object> freeformTags,
        @CustomType.Parameter("id") String id,
        @CustomType.Parameter("isCloneSource") Boolean isCloneSource,
        @CustomType.Parameter("lifecycleDetails") String lifecycleDetails,
        @CustomType.Parameter("name") String name,
        @CustomType.Parameter("provenanceId") String provenanceId,
        @CustomType.Parameter("state") String state,
        @CustomType.Parameter("timeCreated") String timeCreated) {
        this.definedTags = definedTags;
        this.fileSystemId = fileSystemId;
        this.freeformTags = freeformTags;
        this.id = id;
        this.isCloneSource = isCloneSource;
        this.lifecycleDetails = lifecycleDetails;
        this.name = name;
        this.provenanceId = provenanceId;
        this.state = state;
        this.timeCreated = timeCreated;
    }

    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Map<String,Object> definedTags() {
        return this.definedTags;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the file system.
     * 
     */
    public String fileSystemId() {
        return this.fileSystemId;
    }
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Map<String,Object> freeformTags() {
        return this.freeformTags;
    }
    /**
     * @return Filter results by [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm). Must be an OCID of the correct type for the resouce type.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return Specifies whether the snapshot has been cloned. See [Cloning a File System](https://docs.cloud.oracle.com/iaas/Content/File/Tasks/cloningafilesystem.htm).
     * 
     */
    public Boolean isCloneSource() {
        return this.isCloneSource;
    }
    /**
     * @return Additional information about the current &#39;lifecycleState&#39;.
     * 
     */
    public String lifecycleDetails() {
        return this.lifecycleDetails;
    }
    /**
     * @return Name of the snapshot. This value is immutable.
     * 
     */
    public String name() {
        return this.name;
    }
    /**
     * @return An [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) identifying the parent from which this snapshot was cloned. If this snapshot was not cloned, then the `provenanceId` is the same as the snapshot `id` value. If this snapshot was cloned, then the `provenanceId` value is the parent&#39;s `provenanceId`. See [Cloning a File System](https://docs.cloud.oracle.com/iaas/Content/File/Tasks/cloningafilesystem.htm).
     * 
     */
    public String provenanceId() {
        return this.provenanceId;
    }
    /**
     * @return Filter results by the specified lifecycle state. Must be a valid state for the resource type.
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return The date and time the snapshot was created, expressed in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) timestamp format.  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetSnapshotsSnapshot defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private Map<String,Object> definedTags;
        private String fileSystemId;
        private Map<String,Object> freeformTags;
        private String id;
        private Boolean isCloneSource;
        private String lifecycleDetails;
        private String name;
        private String provenanceId;
        private String state;
        private String timeCreated;

        public Builder() {
    	      // Empty
        }

        public Builder(GetSnapshotsSnapshot defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.definedTags = defaults.definedTags;
    	      this.fileSystemId = defaults.fileSystemId;
    	      this.freeformTags = defaults.freeformTags;
    	      this.id = defaults.id;
    	      this.isCloneSource = defaults.isCloneSource;
    	      this.lifecycleDetails = defaults.lifecycleDetails;
    	      this.name = defaults.name;
    	      this.provenanceId = defaults.provenanceId;
    	      this.state = defaults.state;
    	      this.timeCreated = defaults.timeCreated;
        }

        public Builder definedTags(Map<String,Object> definedTags) {
            this.definedTags = Objects.requireNonNull(definedTags);
            return this;
        }
        public Builder fileSystemId(String fileSystemId) {
            this.fileSystemId = Objects.requireNonNull(fileSystemId);
            return this;
        }
        public Builder freeformTags(Map<String,Object> freeformTags) {
            this.freeformTags = Objects.requireNonNull(freeformTags);
            return this;
        }
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        public Builder isCloneSource(Boolean isCloneSource) {
            this.isCloneSource = Objects.requireNonNull(isCloneSource);
            return this;
        }
        public Builder lifecycleDetails(String lifecycleDetails) {
            this.lifecycleDetails = Objects.requireNonNull(lifecycleDetails);
            return this;
        }
        public Builder name(String name) {
            this.name = Objects.requireNonNull(name);
            return this;
        }
        public Builder provenanceId(String provenanceId) {
            this.provenanceId = Objects.requireNonNull(provenanceId);
            return this;
        }
        public Builder state(String state) {
            this.state = Objects.requireNonNull(state);
            return this;
        }
        public Builder timeCreated(String timeCreated) {
            this.timeCreated = Objects.requireNonNull(timeCreated);
            return this;
        }        public GetSnapshotsSnapshot build() {
            return new GetSnapshotsSnapshot(definedTags, fileSystemId, freeformTags, id, isCloneSource, lifecycleDetails, name, provenanceId, state, timeCreated);
        }
    }
}
