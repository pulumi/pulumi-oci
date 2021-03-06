// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Core.outputs.GetVolumeGroupsVolumeGroupSourceDetail;
import com.pulumi.oci.Core.outputs.GetVolumeGroupsVolumeGroupVolumeGroupReplica;
import java.lang.Boolean;
import java.lang.Object;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetVolumeGroupsVolumeGroup {
    /**
     * @return The name of the availability domain.  Example: `Uocm:PHX-AD-1`
     * 
     */
    private final String availabilityDomain;
    private final String backupPolicyId;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    private final String compartmentId;
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    private final Map<String,Object> definedTags;
    /**
     * @return A filter to return only resources that match the given display name exactly.
     * 
     */
    private final String displayName;
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    private final Map<String,Object> freeformTags;
    /**
     * @return The OCID for the volume group.
     * 
     */
    private final String id;
    /**
     * @return Specifies whether the newly created cloned volume group&#39;s data has finished copying from the source volume group or backup.
     * 
     */
    private final Boolean isHydrated;
    private final Boolean preserveVolumeReplica;
    /**
     * @return The aggregate size of the volume group in GBs.
     * 
     */
    private final String sizeInGbs;
    /**
     * @return The aggregate size of the volume group in MBs.
     * 
     */
    private final String sizeInMbs;
    /**
     * @return Specifies the source for a volume group.
     * 
     */
    private final List<GetVolumeGroupsVolumeGroupSourceDetail> sourceDetails;
    /**
     * @return A filter to only return resources that match the given lifecycle state. The state value is case-insensitive.
     * 
     */
    private final String state;
    /**
     * @return The date and time the volume group was created. Format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
     * 
     */
    private final String timeCreated;
    /**
     * @return The list of volume group replicas of this volume group.
     * 
     */
    private final List<GetVolumeGroupsVolumeGroupVolumeGroupReplica> volumeGroupReplicas;
    private final Boolean volumeGroupReplicasDeletion;
    /**
     * @return OCIDs for the volumes in this volume group.
     * 
     */
    private final List<String> volumeIds;

    @CustomType.Constructor
    private GetVolumeGroupsVolumeGroup(
        @CustomType.Parameter("availabilityDomain") String availabilityDomain,
        @CustomType.Parameter("backupPolicyId") String backupPolicyId,
        @CustomType.Parameter("compartmentId") String compartmentId,
        @CustomType.Parameter("definedTags") Map<String,Object> definedTags,
        @CustomType.Parameter("displayName") String displayName,
        @CustomType.Parameter("freeformTags") Map<String,Object> freeformTags,
        @CustomType.Parameter("id") String id,
        @CustomType.Parameter("isHydrated") Boolean isHydrated,
        @CustomType.Parameter("preserveVolumeReplica") Boolean preserveVolumeReplica,
        @CustomType.Parameter("sizeInGbs") String sizeInGbs,
        @CustomType.Parameter("sizeInMbs") String sizeInMbs,
        @CustomType.Parameter("sourceDetails") List<GetVolumeGroupsVolumeGroupSourceDetail> sourceDetails,
        @CustomType.Parameter("state") String state,
        @CustomType.Parameter("timeCreated") String timeCreated,
        @CustomType.Parameter("volumeGroupReplicas") List<GetVolumeGroupsVolumeGroupVolumeGroupReplica> volumeGroupReplicas,
        @CustomType.Parameter("volumeGroupReplicasDeletion") Boolean volumeGroupReplicasDeletion,
        @CustomType.Parameter("volumeIds") List<String> volumeIds) {
        this.availabilityDomain = availabilityDomain;
        this.backupPolicyId = backupPolicyId;
        this.compartmentId = compartmentId;
        this.definedTags = definedTags;
        this.displayName = displayName;
        this.freeformTags = freeformTags;
        this.id = id;
        this.isHydrated = isHydrated;
        this.preserveVolumeReplica = preserveVolumeReplica;
        this.sizeInGbs = sizeInGbs;
        this.sizeInMbs = sizeInMbs;
        this.sourceDetails = sourceDetails;
        this.state = state;
        this.timeCreated = timeCreated;
        this.volumeGroupReplicas = volumeGroupReplicas;
        this.volumeGroupReplicasDeletion = volumeGroupReplicasDeletion;
        this.volumeIds = volumeIds;
    }

    /**
     * @return The name of the availability domain.  Example: `Uocm:PHX-AD-1`
     * 
     */
    public String availabilityDomain() {
        return this.availabilityDomain;
    }
    public String backupPolicyId() {
        return this.backupPolicyId;
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
    public Map<String,Object> definedTags() {
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
    public Map<String,Object> freeformTags() {
        return this.freeformTags;
    }
    /**
     * @return The OCID for the volume group.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return Specifies whether the newly created cloned volume group&#39;s data has finished copying from the source volume group or backup.
     * 
     */
    public Boolean isHydrated() {
        return this.isHydrated;
    }
    public Boolean preserveVolumeReplica() {
        return this.preserveVolumeReplica;
    }
    /**
     * @return The aggregate size of the volume group in GBs.
     * 
     */
    public String sizeInGbs() {
        return this.sizeInGbs;
    }
    /**
     * @return The aggregate size of the volume group in MBs.
     * 
     */
    public String sizeInMbs() {
        return this.sizeInMbs;
    }
    /**
     * @return Specifies the source for a volume group.
     * 
     */
    public List<GetVolumeGroupsVolumeGroupSourceDetail> sourceDetails() {
        return this.sourceDetails;
    }
    /**
     * @return A filter to only return resources that match the given lifecycle state. The state value is case-insensitive.
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return The date and time the volume group was created. Format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return The list of volume group replicas of this volume group.
     * 
     */
    public List<GetVolumeGroupsVolumeGroupVolumeGroupReplica> volumeGroupReplicas() {
        return this.volumeGroupReplicas;
    }
    public Boolean volumeGroupReplicasDeletion() {
        return this.volumeGroupReplicasDeletion;
    }
    /**
     * @return OCIDs for the volumes in this volume group.
     * 
     */
    public List<String> volumeIds() {
        return this.volumeIds;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetVolumeGroupsVolumeGroup defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String availabilityDomain;
        private String backupPolicyId;
        private String compartmentId;
        private Map<String,Object> definedTags;
        private String displayName;
        private Map<String,Object> freeformTags;
        private String id;
        private Boolean isHydrated;
        private Boolean preserveVolumeReplica;
        private String sizeInGbs;
        private String sizeInMbs;
        private List<GetVolumeGroupsVolumeGroupSourceDetail> sourceDetails;
        private String state;
        private String timeCreated;
        private List<GetVolumeGroupsVolumeGroupVolumeGroupReplica> volumeGroupReplicas;
        private Boolean volumeGroupReplicasDeletion;
        private List<String> volumeIds;

        public Builder() {
    	      // Empty
        }

        public Builder(GetVolumeGroupsVolumeGroup defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.availabilityDomain = defaults.availabilityDomain;
    	      this.backupPolicyId = defaults.backupPolicyId;
    	      this.compartmentId = defaults.compartmentId;
    	      this.definedTags = defaults.definedTags;
    	      this.displayName = defaults.displayName;
    	      this.freeformTags = defaults.freeformTags;
    	      this.id = defaults.id;
    	      this.isHydrated = defaults.isHydrated;
    	      this.preserveVolumeReplica = defaults.preserveVolumeReplica;
    	      this.sizeInGbs = defaults.sizeInGbs;
    	      this.sizeInMbs = defaults.sizeInMbs;
    	      this.sourceDetails = defaults.sourceDetails;
    	      this.state = defaults.state;
    	      this.timeCreated = defaults.timeCreated;
    	      this.volumeGroupReplicas = defaults.volumeGroupReplicas;
    	      this.volumeGroupReplicasDeletion = defaults.volumeGroupReplicasDeletion;
    	      this.volumeIds = defaults.volumeIds;
        }

        public Builder availabilityDomain(String availabilityDomain) {
            this.availabilityDomain = Objects.requireNonNull(availabilityDomain);
            return this;
        }
        public Builder backupPolicyId(String backupPolicyId) {
            this.backupPolicyId = Objects.requireNonNull(backupPolicyId);
            return this;
        }
        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        public Builder definedTags(Map<String,Object> definedTags) {
            this.definedTags = Objects.requireNonNull(definedTags);
            return this;
        }
        public Builder displayName(String displayName) {
            this.displayName = Objects.requireNonNull(displayName);
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
        public Builder isHydrated(Boolean isHydrated) {
            this.isHydrated = Objects.requireNonNull(isHydrated);
            return this;
        }
        public Builder preserveVolumeReplica(Boolean preserveVolumeReplica) {
            this.preserveVolumeReplica = Objects.requireNonNull(preserveVolumeReplica);
            return this;
        }
        public Builder sizeInGbs(String sizeInGbs) {
            this.sizeInGbs = Objects.requireNonNull(sizeInGbs);
            return this;
        }
        public Builder sizeInMbs(String sizeInMbs) {
            this.sizeInMbs = Objects.requireNonNull(sizeInMbs);
            return this;
        }
        public Builder sourceDetails(List<GetVolumeGroupsVolumeGroupSourceDetail> sourceDetails) {
            this.sourceDetails = Objects.requireNonNull(sourceDetails);
            return this;
        }
        public Builder sourceDetails(GetVolumeGroupsVolumeGroupSourceDetail... sourceDetails) {
            return sourceDetails(List.of(sourceDetails));
        }
        public Builder state(String state) {
            this.state = Objects.requireNonNull(state);
            return this;
        }
        public Builder timeCreated(String timeCreated) {
            this.timeCreated = Objects.requireNonNull(timeCreated);
            return this;
        }
        public Builder volumeGroupReplicas(List<GetVolumeGroupsVolumeGroupVolumeGroupReplica> volumeGroupReplicas) {
            this.volumeGroupReplicas = Objects.requireNonNull(volumeGroupReplicas);
            return this;
        }
        public Builder volumeGroupReplicas(GetVolumeGroupsVolumeGroupVolumeGroupReplica... volumeGroupReplicas) {
            return volumeGroupReplicas(List.of(volumeGroupReplicas));
        }
        public Builder volumeGroupReplicasDeletion(Boolean volumeGroupReplicasDeletion) {
            this.volumeGroupReplicasDeletion = Objects.requireNonNull(volumeGroupReplicasDeletion);
            return this;
        }
        public Builder volumeIds(List<String> volumeIds) {
            this.volumeIds = Objects.requireNonNull(volumeIds);
            return this;
        }
        public Builder volumeIds(String... volumeIds) {
            return volumeIds(List.of(volumeIds));
        }        public GetVolumeGroupsVolumeGroup build() {
            return new GetVolumeGroupsVolumeGroup(availabilityDomain, backupPolicyId, compartmentId, definedTags, displayName, freeformTags, id, isHydrated, preserveVolumeReplica, sizeInGbs, sizeInMbs, sourceDetails, state, timeCreated, volumeGroupReplicas, volumeGroupReplicasDeletion, volumeIds);
        }
    }
}
