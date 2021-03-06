// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.OsManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.OsManagement.outputs.GetSoftwareSourcesSoftwareSourceAssociatedManagedInstance;
import java.lang.Integer;
import java.lang.Object;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetSoftwareSourcesSoftwareSource {
    /**
     * @return The architecture type supported by the Software Source
     * 
     */
    private final String archType;
    /**
     * @return list of the Managed Instances associated with this Software Sources
     * 
     */
    private final List<GetSoftwareSourcesSoftwareSourceAssociatedManagedInstance> associatedManagedInstances;
    /**
     * @return The yum repository checksum type used by this software source
     * 
     */
    private final String checksumType;
    /**
     * @return The ID of the compartment in which to list resources.
     * 
     */
    private final String compartmentId;
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    private final Map<String,Object> definedTags;
    /**
     * @return Information specified by the user about the software source
     * 
     */
    private final String description;
    /**
     * @return A user-friendly name. Does not have to be unique, and it&#39;s changeable.  Example: `My new resource`
     * 
     */
    private final String displayName;
    /**
     * @return Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    private final Map<String,Object> freeformTags;
    /**
     * @return Fingerprint of the GPG key for this software source
     * 
     */
    private final String gpgKeyFingerprint;
    /**
     * @return ID of the GPG key for this software source
     * 
     */
    private final String gpgKeyId;
    /**
     * @return URL of the GPG key for this software source
     * 
     */
    private final String gpgKeyUrl;
    /**
     * @return OCID for the Software Source
     * 
     */
    private final String id;
    /**
     * @return Email address of the person maintaining this software source
     * 
     */
    private final String maintainerEmail;
    /**
     * @return Name of the person maintaining this software source
     * 
     */
    private final String maintainerName;
    /**
     * @return Phone number of the person maintaining this software source
     * 
     */
    private final String maintainerPhone;
    /**
     * @return Number of packages
     * 
     */
    private final Integer packages;
    /**
     * @return OCID for the parent software source, if there is one
     * 
     */
    private final String parentId;
    /**
     * @return Display name the parent software source, if there is one
     * 
     */
    private final String parentName;
    /**
     * @return Type of the Software Source
     * 
     */
    private final String repoType;
    /**
     * @return The current lifecycle state for the object.
     * 
     */
    private final String state;
    /**
     * @return status of the software source.
     * 
     */
    private final String status;
    /**
     * @return URL for the repostiory
     * 
     */
    private final String url;

    @CustomType.Constructor
    private GetSoftwareSourcesSoftwareSource(
        @CustomType.Parameter("archType") String archType,
        @CustomType.Parameter("associatedManagedInstances") List<GetSoftwareSourcesSoftwareSourceAssociatedManagedInstance> associatedManagedInstances,
        @CustomType.Parameter("checksumType") String checksumType,
        @CustomType.Parameter("compartmentId") String compartmentId,
        @CustomType.Parameter("definedTags") Map<String,Object> definedTags,
        @CustomType.Parameter("description") String description,
        @CustomType.Parameter("displayName") String displayName,
        @CustomType.Parameter("freeformTags") Map<String,Object> freeformTags,
        @CustomType.Parameter("gpgKeyFingerprint") String gpgKeyFingerprint,
        @CustomType.Parameter("gpgKeyId") String gpgKeyId,
        @CustomType.Parameter("gpgKeyUrl") String gpgKeyUrl,
        @CustomType.Parameter("id") String id,
        @CustomType.Parameter("maintainerEmail") String maintainerEmail,
        @CustomType.Parameter("maintainerName") String maintainerName,
        @CustomType.Parameter("maintainerPhone") String maintainerPhone,
        @CustomType.Parameter("packages") Integer packages,
        @CustomType.Parameter("parentId") String parentId,
        @CustomType.Parameter("parentName") String parentName,
        @CustomType.Parameter("repoType") String repoType,
        @CustomType.Parameter("state") String state,
        @CustomType.Parameter("status") String status,
        @CustomType.Parameter("url") String url) {
        this.archType = archType;
        this.associatedManagedInstances = associatedManagedInstances;
        this.checksumType = checksumType;
        this.compartmentId = compartmentId;
        this.definedTags = definedTags;
        this.description = description;
        this.displayName = displayName;
        this.freeformTags = freeformTags;
        this.gpgKeyFingerprint = gpgKeyFingerprint;
        this.gpgKeyId = gpgKeyId;
        this.gpgKeyUrl = gpgKeyUrl;
        this.id = id;
        this.maintainerEmail = maintainerEmail;
        this.maintainerName = maintainerName;
        this.maintainerPhone = maintainerPhone;
        this.packages = packages;
        this.parentId = parentId;
        this.parentName = parentName;
        this.repoType = repoType;
        this.state = state;
        this.status = status;
        this.url = url;
    }

    /**
     * @return The architecture type supported by the Software Source
     * 
     */
    public String archType() {
        return this.archType;
    }
    /**
     * @return list of the Managed Instances associated with this Software Sources
     * 
     */
    public List<GetSoftwareSourcesSoftwareSourceAssociatedManagedInstance> associatedManagedInstances() {
        return this.associatedManagedInstances;
    }
    /**
     * @return The yum repository checksum type used by this software source
     * 
     */
    public String checksumType() {
        return this.checksumType;
    }
    /**
     * @return The ID of the compartment in which to list resources.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Map<String,Object> definedTags() {
        return this.definedTags;
    }
    /**
     * @return Information specified by the user about the software source
     * 
     */
    public String description() {
        return this.description;
    }
    /**
     * @return A user-friendly name. Does not have to be unique, and it&#39;s changeable.  Example: `My new resource`
     * 
     */
    public String displayName() {
        return this.displayName;
    }
    /**
     * @return Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Map<String,Object> freeformTags() {
        return this.freeformTags;
    }
    /**
     * @return Fingerprint of the GPG key for this software source
     * 
     */
    public String gpgKeyFingerprint() {
        return this.gpgKeyFingerprint;
    }
    /**
     * @return ID of the GPG key for this software source
     * 
     */
    public String gpgKeyId() {
        return this.gpgKeyId;
    }
    /**
     * @return URL of the GPG key for this software source
     * 
     */
    public String gpgKeyUrl() {
        return this.gpgKeyUrl;
    }
    /**
     * @return OCID for the Software Source
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return Email address of the person maintaining this software source
     * 
     */
    public String maintainerEmail() {
        return this.maintainerEmail;
    }
    /**
     * @return Name of the person maintaining this software source
     * 
     */
    public String maintainerName() {
        return this.maintainerName;
    }
    /**
     * @return Phone number of the person maintaining this software source
     * 
     */
    public String maintainerPhone() {
        return this.maintainerPhone;
    }
    /**
     * @return Number of packages
     * 
     */
    public Integer packages() {
        return this.packages;
    }
    /**
     * @return OCID for the parent software source, if there is one
     * 
     */
    public String parentId() {
        return this.parentId;
    }
    /**
     * @return Display name the parent software source, if there is one
     * 
     */
    public String parentName() {
        return this.parentName;
    }
    /**
     * @return Type of the Software Source
     * 
     */
    public String repoType() {
        return this.repoType;
    }
    /**
     * @return The current lifecycle state for the object.
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return status of the software source.
     * 
     */
    public String status() {
        return this.status;
    }
    /**
     * @return URL for the repostiory
     * 
     */
    public String url() {
        return this.url;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetSoftwareSourcesSoftwareSource defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String archType;
        private List<GetSoftwareSourcesSoftwareSourceAssociatedManagedInstance> associatedManagedInstances;
        private String checksumType;
        private String compartmentId;
        private Map<String,Object> definedTags;
        private String description;
        private String displayName;
        private Map<String,Object> freeformTags;
        private String gpgKeyFingerprint;
        private String gpgKeyId;
        private String gpgKeyUrl;
        private String id;
        private String maintainerEmail;
        private String maintainerName;
        private String maintainerPhone;
        private Integer packages;
        private String parentId;
        private String parentName;
        private String repoType;
        private String state;
        private String status;
        private String url;

        public Builder() {
    	      // Empty
        }

        public Builder(GetSoftwareSourcesSoftwareSource defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.archType = defaults.archType;
    	      this.associatedManagedInstances = defaults.associatedManagedInstances;
    	      this.checksumType = defaults.checksumType;
    	      this.compartmentId = defaults.compartmentId;
    	      this.definedTags = defaults.definedTags;
    	      this.description = defaults.description;
    	      this.displayName = defaults.displayName;
    	      this.freeformTags = defaults.freeformTags;
    	      this.gpgKeyFingerprint = defaults.gpgKeyFingerprint;
    	      this.gpgKeyId = defaults.gpgKeyId;
    	      this.gpgKeyUrl = defaults.gpgKeyUrl;
    	      this.id = defaults.id;
    	      this.maintainerEmail = defaults.maintainerEmail;
    	      this.maintainerName = defaults.maintainerName;
    	      this.maintainerPhone = defaults.maintainerPhone;
    	      this.packages = defaults.packages;
    	      this.parentId = defaults.parentId;
    	      this.parentName = defaults.parentName;
    	      this.repoType = defaults.repoType;
    	      this.state = defaults.state;
    	      this.status = defaults.status;
    	      this.url = defaults.url;
        }

        public Builder archType(String archType) {
            this.archType = Objects.requireNonNull(archType);
            return this;
        }
        public Builder associatedManagedInstances(List<GetSoftwareSourcesSoftwareSourceAssociatedManagedInstance> associatedManagedInstances) {
            this.associatedManagedInstances = Objects.requireNonNull(associatedManagedInstances);
            return this;
        }
        public Builder associatedManagedInstances(GetSoftwareSourcesSoftwareSourceAssociatedManagedInstance... associatedManagedInstances) {
            return associatedManagedInstances(List.of(associatedManagedInstances));
        }
        public Builder checksumType(String checksumType) {
            this.checksumType = Objects.requireNonNull(checksumType);
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
        public Builder description(String description) {
            this.description = Objects.requireNonNull(description);
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
        public Builder gpgKeyFingerprint(String gpgKeyFingerprint) {
            this.gpgKeyFingerprint = Objects.requireNonNull(gpgKeyFingerprint);
            return this;
        }
        public Builder gpgKeyId(String gpgKeyId) {
            this.gpgKeyId = Objects.requireNonNull(gpgKeyId);
            return this;
        }
        public Builder gpgKeyUrl(String gpgKeyUrl) {
            this.gpgKeyUrl = Objects.requireNonNull(gpgKeyUrl);
            return this;
        }
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        public Builder maintainerEmail(String maintainerEmail) {
            this.maintainerEmail = Objects.requireNonNull(maintainerEmail);
            return this;
        }
        public Builder maintainerName(String maintainerName) {
            this.maintainerName = Objects.requireNonNull(maintainerName);
            return this;
        }
        public Builder maintainerPhone(String maintainerPhone) {
            this.maintainerPhone = Objects.requireNonNull(maintainerPhone);
            return this;
        }
        public Builder packages(Integer packages) {
            this.packages = Objects.requireNonNull(packages);
            return this;
        }
        public Builder parentId(String parentId) {
            this.parentId = Objects.requireNonNull(parentId);
            return this;
        }
        public Builder parentName(String parentName) {
            this.parentName = Objects.requireNonNull(parentName);
            return this;
        }
        public Builder repoType(String repoType) {
            this.repoType = Objects.requireNonNull(repoType);
            return this;
        }
        public Builder state(String state) {
            this.state = Objects.requireNonNull(state);
            return this;
        }
        public Builder status(String status) {
            this.status = Objects.requireNonNull(status);
            return this;
        }
        public Builder url(String url) {
            this.url = Objects.requireNonNull(url);
            return this;
        }        public GetSoftwareSourcesSoftwareSource build() {
            return new GetSoftwareSourcesSoftwareSource(archType, associatedManagedInstances, checksumType, compartmentId, definedTags, description, displayName, freeformTags, gpgKeyFingerprint, gpgKeyId, gpgKeyUrl, id, maintainerEmail, maintainerName, maintainerPhone, packages, parentId, parentName, repoType, state, status, url);
        }
    }
}
