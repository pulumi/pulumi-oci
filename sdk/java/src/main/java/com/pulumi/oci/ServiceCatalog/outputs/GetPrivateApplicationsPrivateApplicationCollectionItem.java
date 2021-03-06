// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ServiceCatalog.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.ServiceCatalog.outputs.GetPrivateApplicationsPrivateApplicationCollectionItemLogo;
import com.pulumi.oci.ServiceCatalog.outputs.GetPrivateApplicationsPrivateApplicationCollectionItemPackageDetail;
import java.lang.Object;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetPrivateApplicationsPrivateApplicationCollectionItem {
    /**
     * @return The unique identifier for the compartment.
     * 
     */
    private final String compartmentId;
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    private final Map<String,Object> definedTags;
    /**
     * @return Exact match name filter.
     * 
     */
    private final String displayName;
    /**
     * @return Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    private final Map<String,Object> freeformTags;
    /**
     * @return The unique identifier for the private application in Marketplace.
     * 
     */
    private final String id;
    private final String logoFileBase64encoded;
    /**
     * @return The model for uploaded binary data, like logos and images.
     * 
     */
    private final List<GetPrivateApplicationsPrivateApplicationCollectionItemLogo> logos;
    /**
     * @return A long description of the private application.
     * 
     */
    private final String longDescription;
    private final List<GetPrivateApplicationsPrivateApplicationCollectionItemPackageDetail> packageDetails;
    /**
     * @return Type of packages within this private application.
     * 
     */
    private final String packageType;
    /**
     * @return A short description of the private application.
     * 
     */
    private final String shortDescription;
    /**
     * @return The lifecycle state of the private application.
     * 
     */
    private final String state;
    /**
     * @return The date and time the private application was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.  Example: `2021-05-26T21:10:29.600Z`
     * 
     */
    private final String timeCreated;
    /**
     * @return The date and time the private application was last modified, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.  Example: `2021-12-10T05:10:29.721Z`
     * 
     */
    private final String timeUpdated;

    @CustomType.Constructor
    private GetPrivateApplicationsPrivateApplicationCollectionItem(
        @CustomType.Parameter("compartmentId") String compartmentId,
        @CustomType.Parameter("definedTags") Map<String,Object> definedTags,
        @CustomType.Parameter("displayName") String displayName,
        @CustomType.Parameter("freeformTags") Map<String,Object> freeformTags,
        @CustomType.Parameter("id") String id,
        @CustomType.Parameter("logoFileBase64encoded") String logoFileBase64encoded,
        @CustomType.Parameter("logos") List<GetPrivateApplicationsPrivateApplicationCollectionItemLogo> logos,
        @CustomType.Parameter("longDescription") String longDescription,
        @CustomType.Parameter("packageDetails") List<GetPrivateApplicationsPrivateApplicationCollectionItemPackageDetail> packageDetails,
        @CustomType.Parameter("packageType") String packageType,
        @CustomType.Parameter("shortDescription") String shortDescription,
        @CustomType.Parameter("state") String state,
        @CustomType.Parameter("timeCreated") String timeCreated,
        @CustomType.Parameter("timeUpdated") String timeUpdated) {
        this.compartmentId = compartmentId;
        this.definedTags = definedTags;
        this.displayName = displayName;
        this.freeformTags = freeformTags;
        this.id = id;
        this.logoFileBase64encoded = logoFileBase64encoded;
        this.logos = logos;
        this.longDescription = longDescription;
        this.packageDetails = packageDetails;
        this.packageType = packageType;
        this.shortDescription = shortDescription;
        this.state = state;
        this.timeCreated = timeCreated;
        this.timeUpdated = timeUpdated;
    }

    /**
     * @return The unique identifier for the compartment.
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
     * @return Exact match name filter.
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
     * @return The unique identifier for the private application in Marketplace.
     * 
     */
    public String id() {
        return this.id;
    }
    public String logoFileBase64encoded() {
        return this.logoFileBase64encoded;
    }
    /**
     * @return The model for uploaded binary data, like logos and images.
     * 
     */
    public List<GetPrivateApplicationsPrivateApplicationCollectionItemLogo> logos() {
        return this.logos;
    }
    /**
     * @return A long description of the private application.
     * 
     */
    public String longDescription() {
        return this.longDescription;
    }
    public List<GetPrivateApplicationsPrivateApplicationCollectionItemPackageDetail> packageDetails() {
        return this.packageDetails;
    }
    /**
     * @return Type of packages within this private application.
     * 
     */
    public String packageType() {
        return this.packageType;
    }
    /**
     * @return A short description of the private application.
     * 
     */
    public String shortDescription() {
        return this.shortDescription;
    }
    /**
     * @return The lifecycle state of the private application.
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return The date and time the private application was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.  Example: `2021-05-26T21:10:29.600Z`
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return The date and time the private application was last modified, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.  Example: `2021-12-10T05:10:29.721Z`
     * 
     */
    public String timeUpdated() {
        return this.timeUpdated;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetPrivateApplicationsPrivateApplicationCollectionItem defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String compartmentId;
        private Map<String,Object> definedTags;
        private String displayName;
        private Map<String,Object> freeformTags;
        private String id;
        private String logoFileBase64encoded;
        private List<GetPrivateApplicationsPrivateApplicationCollectionItemLogo> logos;
        private String longDescription;
        private List<GetPrivateApplicationsPrivateApplicationCollectionItemPackageDetail> packageDetails;
        private String packageType;
        private String shortDescription;
        private String state;
        private String timeCreated;
        private String timeUpdated;

        public Builder() {
    	      // Empty
        }

        public Builder(GetPrivateApplicationsPrivateApplicationCollectionItem defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.definedTags = defaults.definedTags;
    	      this.displayName = defaults.displayName;
    	      this.freeformTags = defaults.freeformTags;
    	      this.id = defaults.id;
    	      this.logoFileBase64encoded = defaults.logoFileBase64encoded;
    	      this.logos = defaults.logos;
    	      this.longDescription = defaults.longDescription;
    	      this.packageDetails = defaults.packageDetails;
    	      this.packageType = defaults.packageType;
    	      this.shortDescription = defaults.shortDescription;
    	      this.state = defaults.state;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeUpdated = defaults.timeUpdated;
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
        public Builder logoFileBase64encoded(String logoFileBase64encoded) {
            this.logoFileBase64encoded = Objects.requireNonNull(logoFileBase64encoded);
            return this;
        }
        public Builder logos(List<GetPrivateApplicationsPrivateApplicationCollectionItemLogo> logos) {
            this.logos = Objects.requireNonNull(logos);
            return this;
        }
        public Builder logos(GetPrivateApplicationsPrivateApplicationCollectionItemLogo... logos) {
            return logos(List.of(logos));
        }
        public Builder longDescription(String longDescription) {
            this.longDescription = Objects.requireNonNull(longDescription);
            return this;
        }
        public Builder packageDetails(List<GetPrivateApplicationsPrivateApplicationCollectionItemPackageDetail> packageDetails) {
            this.packageDetails = Objects.requireNonNull(packageDetails);
            return this;
        }
        public Builder packageDetails(GetPrivateApplicationsPrivateApplicationCollectionItemPackageDetail... packageDetails) {
            return packageDetails(List.of(packageDetails));
        }
        public Builder packageType(String packageType) {
            this.packageType = Objects.requireNonNull(packageType);
            return this;
        }
        public Builder shortDescription(String shortDescription) {
            this.shortDescription = Objects.requireNonNull(shortDescription);
            return this;
        }
        public Builder state(String state) {
            this.state = Objects.requireNonNull(state);
            return this;
        }
        public Builder timeCreated(String timeCreated) {
            this.timeCreated = Objects.requireNonNull(timeCreated);
            return this;
        }
        public Builder timeUpdated(String timeUpdated) {
            this.timeUpdated = Objects.requireNonNull(timeUpdated);
            return this;
        }        public GetPrivateApplicationsPrivateApplicationCollectionItem build() {
            return new GetPrivateApplicationsPrivateApplicationCollectionItem(compartmentId, definedTags, displayName, freeformTags, id, logoFileBase64encoded, logos, longDescription, packageDetails, packageType, shortDescription, state, timeCreated, timeUpdated);
        }
    }
}
