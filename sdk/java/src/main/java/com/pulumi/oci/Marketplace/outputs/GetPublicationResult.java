// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Marketplace.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Marketplace.outputs.GetPublicationIcon;
import com.pulumi.oci.Marketplace.outputs.GetPublicationPackageDetail;
import com.pulumi.oci.Marketplace.outputs.GetPublicationSupportContact;
import com.pulumi.oci.Marketplace.outputs.GetPublicationSupportedOperatingSystem;
import java.lang.Boolean;
import java.lang.Object;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetPublicationResult {
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment where the publication exists.
     * 
     */
    private String compartmentId;
    /**
     * @return The defined tags associated with this resource, if any. Each key is predefined and scoped to namespaces. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    private Map<String,Object> definedTags;
    /**
     * @return The freeform tags associated with this resource, if any. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    private Map<String,Object> freeformTags;
    /**
     * @return The model for upload data for images and icons.
     * 
     */
    private List<GetPublicationIcon> icons;
    /**
     * @return The unique identifier for the publication in Marketplace.
     * 
     */
    private String id;
    private Boolean isAgreementAcknowledged;
    /**
     * @return The publisher category to which the publication belongs. The publisher category informs where the listing appears for use.
     * 
     */
    private String listingType;
    /**
     * @return A long description of the publication to use in the listing.
     * 
     */
    private String longDescription;
    /**
     * @return The name of the operating system.
     * 
     */
    private String name;
    private List<GetPublicationPackageDetail> packageDetails;
    /**
     * @return The listing&#39;s package type.
     * 
     */
    private String packageType;
    private String publicationId;
    /**
     * @return A short description of the publication to use in the listing.
     * 
     */
    private String shortDescription;
    /**
     * @return The lifecycle state of the publication.
     * 
     */
    private String state;
    /**
     * @return Contact information for getting support from the publisher for the listing.
     * 
     */
    private List<GetPublicationSupportContact> supportContacts;
    /**
     * @return The list of operating systems supported by the listing.
     * 
     */
    private List<GetPublicationSupportedOperatingSystem> supportedOperatingSystems;
    /**
     * @return The date and time the publication was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    private String timeCreated;

    private GetPublicationResult() {}
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment where the publication exists.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return The defined tags associated with this resource, if any. Each key is predefined and scoped to namespaces. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Map<String,Object> definedTags() {
        return this.definedTags;
    }
    /**
     * @return The freeform tags associated with this resource, if any. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Map<String,Object> freeformTags() {
        return this.freeformTags;
    }
    /**
     * @return The model for upload data for images and icons.
     * 
     */
    public List<GetPublicationIcon> icons() {
        return this.icons;
    }
    /**
     * @return The unique identifier for the publication in Marketplace.
     * 
     */
    public String id() {
        return this.id;
    }
    public Boolean isAgreementAcknowledged() {
        return this.isAgreementAcknowledged;
    }
    /**
     * @return The publisher category to which the publication belongs. The publisher category informs where the listing appears for use.
     * 
     */
    public String listingType() {
        return this.listingType;
    }
    /**
     * @return A long description of the publication to use in the listing.
     * 
     */
    public String longDescription() {
        return this.longDescription;
    }
    /**
     * @return The name of the operating system.
     * 
     */
    public String name() {
        return this.name;
    }
    public List<GetPublicationPackageDetail> packageDetails() {
        return this.packageDetails;
    }
    /**
     * @return The listing&#39;s package type.
     * 
     */
    public String packageType() {
        return this.packageType;
    }
    public String publicationId() {
        return this.publicationId;
    }
    /**
     * @return A short description of the publication to use in the listing.
     * 
     */
    public String shortDescription() {
        return this.shortDescription;
    }
    /**
     * @return The lifecycle state of the publication.
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return Contact information for getting support from the publisher for the listing.
     * 
     */
    public List<GetPublicationSupportContact> supportContacts() {
        return this.supportContacts;
    }
    /**
     * @return The list of operating systems supported by the listing.
     * 
     */
    public List<GetPublicationSupportedOperatingSystem> supportedOperatingSystems() {
        return this.supportedOperatingSystems;
    }
    /**
     * @return The date and time the publication was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetPublicationResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String compartmentId;
        private Map<String,Object> definedTags;
        private Map<String,Object> freeformTags;
        private List<GetPublicationIcon> icons;
        private String id;
        private Boolean isAgreementAcknowledged;
        private String listingType;
        private String longDescription;
        private String name;
        private List<GetPublicationPackageDetail> packageDetails;
        private String packageType;
        private String publicationId;
        private String shortDescription;
        private String state;
        private List<GetPublicationSupportContact> supportContacts;
        private List<GetPublicationSupportedOperatingSystem> supportedOperatingSystems;
        private String timeCreated;
        public Builder() {}
        public Builder(GetPublicationResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.definedTags = defaults.definedTags;
    	      this.freeformTags = defaults.freeformTags;
    	      this.icons = defaults.icons;
    	      this.id = defaults.id;
    	      this.isAgreementAcknowledged = defaults.isAgreementAcknowledged;
    	      this.listingType = defaults.listingType;
    	      this.longDescription = defaults.longDescription;
    	      this.name = defaults.name;
    	      this.packageDetails = defaults.packageDetails;
    	      this.packageType = defaults.packageType;
    	      this.publicationId = defaults.publicationId;
    	      this.shortDescription = defaults.shortDescription;
    	      this.state = defaults.state;
    	      this.supportContacts = defaults.supportContacts;
    	      this.supportedOperatingSystems = defaults.supportedOperatingSystems;
    	      this.timeCreated = defaults.timeCreated;
        }

        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        @CustomType.Setter
        public Builder definedTags(Map<String,Object> definedTags) {
            this.definedTags = Objects.requireNonNull(definedTags);
            return this;
        }
        @CustomType.Setter
        public Builder freeformTags(Map<String,Object> freeformTags) {
            this.freeformTags = Objects.requireNonNull(freeformTags);
            return this;
        }
        @CustomType.Setter
        public Builder icons(List<GetPublicationIcon> icons) {
            this.icons = Objects.requireNonNull(icons);
            return this;
        }
        public Builder icons(GetPublicationIcon... icons) {
            return icons(List.of(icons));
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        @CustomType.Setter
        public Builder isAgreementAcknowledged(Boolean isAgreementAcknowledged) {
            this.isAgreementAcknowledged = Objects.requireNonNull(isAgreementAcknowledged);
            return this;
        }
        @CustomType.Setter
        public Builder listingType(String listingType) {
            this.listingType = Objects.requireNonNull(listingType);
            return this;
        }
        @CustomType.Setter
        public Builder longDescription(String longDescription) {
            this.longDescription = Objects.requireNonNull(longDescription);
            return this;
        }
        @CustomType.Setter
        public Builder name(String name) {
            this.name = Objects.requireNonNull(name);
            return this;
        }
        @CustomType.Setter
        public Builder packageDetails(List<GetPublicationPackageDetail> packageDetails) {
            this.packageDetails = Objects.requireNonNull(packageDetails);
            return this;
        }
        public Builder packageDetails(GetPublicationPackageDetail... packageDetails) {
            return packageDetails(List.of(packageDetails));
        }
        @CustomType.Setter
        public Builder packageType(String packageType) {
            this.packageType = Objects.requireNonNull(packageType);
            return this;
        }
        @CustomType.Setter
        public Builder publicationId(String publicationId) {
            this.publicationId = Objects.requireNonNull(publicationId);
            return this;
        }
        @CustomType.Setter
        public Builder shortDescription(String shortDescription) {
            this.shortDescription = Objects.requireNonNull(shortDescription);
            return this;
        }
        @CustomType.Setter
        public Builder state(String state) {
            this.state = Objects.requireNonNull(state);
            return this;
        }
        @CustomType.Setter
        public Builder supportContacts(List<GetPublicationSupportContact> supportContacts) {
            this.supportContacts = Objects.requireNonNull(supportContacts);
            return this;
        }
        public Builder supportContacts(GetPublicationSupportContact... supportContacts) {
            return supportContacts(List.of(supportContacts));
        }
        @CustomType.Setter
        public Builder supportedOperatingSystems(List<GetPublicationSupportedOperatingSystem> supportedOperatingSystems) {
            this.supportedOperatingSystems = Objects.requireNonNull(supportedOperatingSystems);
            return this;
        }
        public Builder supportedOperatingSystems(GetPublicationSupportedOperatingSystem... supportedOperatingSystems) {
            return supportedOperatingSystems(List.of(supportedOperatingSystems));
        }
        @CustomType.Setter
        public Builder timeCreated(String timeCreated) {
            this.timeCreated = Objects.requireNonNull(timeCreated);
            return this;
        }
        public GetPublicationResult build() {
            final var o = new GetPublicationResult();
            o.compartmentId = compartmentId;
            o.definedTags = definedTags;
            o.freeformTags = freeformTags;
            o.icons = icons;
            o.id = id;
            o.isAgreementAcknowledged = isAgreementAcknowledged;
            o.listingType = listingType;
            o.longDescription = longDescription;
            o.name = name;
            o.packageDetails = packageDetails;
            o.packageType = packageType;
            o.publicationId = publicationId;
            o.shortDescription = shortDescription;
            o.state = state;
            o.supportContacts = supportContacts;
            o.supportedOperatingSystems = supportedOperatingSystems;
            o.timeCreated = timeCreated;
            return o;
        }
    }
}