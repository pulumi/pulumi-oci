// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CloudBridge.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Object;
import java.lang.String;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetApplianceImagesApplianceImageCollectionItem {
    /**
     * @return The checksum of the image file.
     * 
     */
    private String checksum;
    /**
     * @return The defined tags associated with this resource, if any. Each key is predefined and scoped to namespaces. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    private Map<String,Object> definedTags;
    /**
     * @return A filter to return only resources that match the entire display name given.
     * 
     */
    private String displayName;
    /**
     * @return The URL from which the appliance image can be downloaded.
     * 
     */
    private String downloadUrl;
    /**
     * @return The name of the appliance Image file.
     * 
     */
    private String fileName;
    /**
     * @return The file format of the image file.
     * 
     */
    private String format;
    /**
     * @return The freeform tags associated with this resource, if any. Each tag is a simple key-value pair with no predefined name, type, or namespace/scope. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    private Map<String,Object> freeformTags;
    /**
     * @return Unique identifier that is immutable on creation.
     * 
     */
    private String id;
    /**
     * @return The virtualization platform that the image file supports.
     * 
     */
    private String platform;
    /**
     * @return The size of the image file in megabytes.
     * 
     */
    private String sizeInMbs;
    /**
     * @return The current state of the appliance image.
     * 
     */
    private String state;
    /**
     * @return The time when the appliance image was created.An RFC3339 formatted datetime string.
     * 
     */
    private String timeCreated;
    /**
     * @return The time when the appliance image was last updated. An RFC3339 formatted datetime string.
     * 
     */
    private String timeUpdated;
    /**
     * @return The version of the image file.
     * 
     */
    private String version;

    private GetApplianceImagesApplianceImageCollectionItem() {}
    /**
     * @return The checksum of the image file.
     * 
     */
    public String checksum() {
        return this.checksum;
    }
    /**
     * @return The defined tags associated with this resource, if any. Each key is predefined and scoped to namespaces. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Map<String,Object> definedTags() {
        return this.definedTags;
    }
    /**
     * @return A filter to return only resources that match the entire display name given.
     * 
     */
    public String displayName() {
        return this.displayName;
    }
    /**
     * @return The URL from which the appliance image can be downloaded.
     * 
     */
    public String downloadUrl() {
        return this.downloadUrl;
    }
    /**
     * @return The name of the appliance Image file.
     * 
     */
    public String fileName() {
        return this.fileName;
    }
    /**
     * @return The file format of the image file.
     * 
     */
    public String format() {
        return this.format;
    }
    /**
     * @return The freeform tags associated with this resource, if any. Each tag is a simple key-value pair with no predefined name, type, or namespace/scope. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Map<String,Object> freeformTags() {
        return this.freeformTags;
    }
    /**
     * @return Unique identifier that is immutable on creation.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return The virtualization platform that the image file supports.
     * 
     */
    public String platform() {
        return this.platform;
    }
    /**
     * @return The size of the image file in megabytes.
     * 
     */
    public String sizeInMbs() {
        return this.sizeInMbs;
    }
    /**
     * @return The current state of the appliance image.
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return The time when the appliance image was created.An RFC3339 formatted datetime string.
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return The time when the appliance image was last updated. An RFC3339 formatted datetime string.
     * 
     */
    public String timeUpdated() {
        return this.timeUpdated;
    }
    /**
     * @return The version of the image file.
     * 
     */
    public String version() {
        return this.version;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetApplianceImagesApplianceImageCollectionItem defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String checksum;
        private Map<String,Object> definedTags;
        private String displayName;
        private String downloadUrl;
        private String fileName;
        private String format;
        private Map<String,Object> freeformTags;
        private String id;
        private String platform;
        private String sizeInMbs;
        private String state;
        private String timeCreated;
        private String timeUpdated;
        private String version;
        public Builder() {}
        public Builder(GetApplianceImagesApplianceImageCollectionItem defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.checksum = defaults.checksum;
    	      this.definedTags = defaults.definedTags;
    	      this.displayName = defaults.displayName;
    	      this.downloadUrl = defaults.downloadUrl;
    	      this.fileName = defaults.fileName;
    	      this.format = defaults.format;
    	      this.freeformTags = defaults.freeformTags;
    	      this.id = defaults.id;
    	      this.platform = defaults.platform;
    	      this.sizeInMbs = defaults.sizeInMbs;
    	      this.state = defaults.state;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeUpdated = defaults.timeUpdated;
    	      this.version = defaults.version;
        }

        @CustomType.Setter
        public Builder checksum(String checksum) {
            this.checksum = Objects.requireNonNull(checksum);
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
        public Builder downloadUrl(String downloadUrl) {
            this.downloadUrl = Objects.requireNonNull(downloadUrl);
            return this;
        }
        @CustomType.Setter
        public Builder fileName(String fileName) {
            this.fileName = Objects.requireNonNull(fileName);
            return this;
        }
        @CustomType.Setter
        public Builder format(String format) {
            this.format = Objects.requireNonNull(format);
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
        public Builder platform(String platform) {
            this.platform = Objects.requireNonNull(platform);
            return this;
        }
        @CustomType.Setter
        public Builder sizeInMbs(String sizeInMbs) {
            this.sizeInMbs = Objects.requireNonNull(sizeInMbs);
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
        @CustomType.Setter
        public Builder version(String version) {
            this.version = Objects.requireNonNull(version);
            return this;
        }
        public GetApplianceImagesApplianceImageCollectionItem build() {
            final var o = new GetApplianceImagesApplianceImageCollectionItem();
            o.checksum = checksum;
            o.definedTags = definedTags;
            o.displayName = displayName;
            o.downloadUrl = downloadUrl;
            o.fileName = fileName;
            o.format = format;
            o.freeformTags = freeformTags;
            o.id = id;
            o.platform = platform;
            o.sizeInMbs = sizeInMbs;
            o.state = state;
            o.timeCreated = timeCreated;
            o.timeUpdated = timeUpdated;
            o.version = version;
            return o;
        }
    }
}