// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ServiceCatalog.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.ServiceCatalog.outputs.GetPrivateApplicationLogo;
import com.pulumi.oci.ServiceCatalog.outputs.GetPrivateApplicationPackageDetail;
import java.lang.Object;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetPrivateApplicationResult {
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment where the private application resides.
     * 
     */
    private String compartmentId;
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    private Map<String,Object> definedTags;
    /**
     * @return The name used to refer to the uploaded data.
     * 
     */
    private String displayName;
    /**
     * @return Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    private Map<String,Object> freeformTags;
    /**
     * @return The unique identifier for the private application in Marketplace.
     * 
     */
    private String id;
    private String logoFileBase64encoded;
    /**
     * @return The model for uploaded binary data, like logos and images.
     * 
     */
    private List<GetPrivateApplicationLogo> logos;
    /**
     * @return A long description of the private application.
     * 
     */
    private String longDescription;
    private List<GetPrivateApplicationPackageDetail> packageDetails;
    /**
     * @return Type of packages within this private application.
     * 
     */
    private String packageType;
    private String privateApplicationId;
    /**
     * @return A short description of the private application.
     * 
     */
    private String shortDescription;
    /**
     * @return The lifecycle state of the private application.
     * 
     */
    private String state;
    /**
     * @return The date and time the private application was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.  Example: `2021-05-26T21:10:29.600Z`
     * 
     */
    private String timeCreated;
    /**
     * @return The date and time the private application was last modified, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.  Example: `2021-12-10T05:10:29.721Z`
     * 
     */
    private String timeUpdated;

    private GetPrivateApplicationResult() {}
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment where the private application resides.
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
     * @return The name used to refer to the uploaded data.
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
    public List<GetPrivateApplicationLogo> logos() {
        return this.logos;
    }
    /**
     * @return A long description of the private application.
     * 
     */
    public String longDescription() {
        return this.longDescription;
    }
    public List<GetPrivateApplicationPackageDetail> packageDetails() {
        return this.packageDetails;
    }
    /**
     * @return Type of packages within this private application.
     * 
     */
    public String packageType() {
        return this.packageType;
    }
    public String privateApplicationId() {
        return this.privateApplicationId;
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

    public static Builder builder(GetPrivateApplicationResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String compartmentId;
        private Map<String,Object> definedTags;
        private String displayName;
        private Map<String,Object> freeformTags;
        private String id;
        private String logoFileBase64encoded;
        private List<GetPrivateApplicationLogo> logos;
        private String longDescription;
        private List<GetPrivateApplicationPackageDetail> packageDetails;
        private String packageType;
        private String privateApplicationId;
        private String shortDescription;
        private String state;
        private String timeCreated;
        private String timeUpdated;
        public Builder() {}
        public Builder(GetPrivateApplicationResult defaults) {
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
    	      this.privateApplicationId = defaults.privateApplicationId;
    	      this.shortDescription = defaults.shortDescription;
    	      this.state = defaults.state;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeUpdated = defaults.timeUpdated;
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
        public Builder displayName(String displayName) {
            this.displayName = Objects.requireNonNull(displayName);
            return this;
        }
        @CustomType.Setter
        public Builder freeformTags(Map<String,Object> freeformTags) {
            this.freeformTags = Objects.requireNonNull(freeformTags);
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        @CustomType.Setter
        public Builder logoFileBase64encoded(String logoFileBase64encoded) {
            this.logoFileBase64encoded = Objects.requireNonNull(logoFileBase64encoded);
            return this;
        }
        @CustomType.Setter
        public Builder logos(List<GetPrivateApplicationLogo> logos) {
            this.logos = Objects.requireNonNull(logos);
            return this;
        }
        public Builder logos(GetPrivateApplicationLogo... logos) {
            return logos(List.of(logos));
        }
        @CustomType.Setter
        public Builder longDescription(String longDescription) {
            this.longDescription = Objects.requireNonNull(longDescription);
            return this;
        }
        @CustomType.Setter
        public Builder packageDetails(List<GetPrivateApplicationPackageDetail> packageDetails) {
            this.packageDetails = Objects.requireNonNull(packageDetails);
            return this;
        }
        public Builder packageDetails(GetPrivateApplicationPackageDetail... packageDetails) {
            return packageDetails(List.of(packageDetails));
        }
        @CustomType.Setter
        public Builder packageType(String packageType) {
            this.packageType = Objects.requireNonNull(packageType);
            return this;
        }
        @CustomType.Setter
        public Builder privateApplicationId(String privateApplicationId) {
            this.privateApplicationId = Objects.requireNonNull(privateApplicationId);
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
        public Builder timeCreated(String timeCreated) {
            this.timeCreated = Objects.requireNonNull(timeCreated);
            return this;
        }
        @CustomType.Setter
        public Builder timeUpdated(String timeUpdated) {
            this.timeUpdated = Objects.requireNonNull(timeUpdated);
            return this;
        }
        public GetPrivateApplicationResult build() {
            final var o = new GetPrivateApplicationResult();
            o.compartmentId = compartmentId;
            o.definedTags = definedTags;
            o.displayName = displayName;
            o.freeformTags = freeformTags;
            o.id = id;
            o.logoFileBase64encoded = logoFileBase64encoded;
            o.logos = logos;
            o.longDescription = longDescription;
            o.packageDetails = packageDetails;
            o.packageType = packageType;
            o.privateApplicationId = privateApplicationId;
            o.shortDescription = shortDescription;
            o.state = state;
            o.timeCreated = timeCreated;
            o.timeUpdated = timeUpdated;
            return o;
        }
    }
}