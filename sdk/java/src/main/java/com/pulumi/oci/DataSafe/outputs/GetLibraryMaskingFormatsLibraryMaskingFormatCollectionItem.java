// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataSafe.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DataSafe.outputs.GetLibraryMaskingFormatsLibraryMaskingFormatCollectionItemFormatEntry;
import java.lang.Object;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetLibraryMaskingFormatsLibraryMaskingFormatCollectionItem {
    /**
     * @return A filter to return only resources that match the specified compartment OCID.
     * 
     */
    private String compartmentId;
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    private Map<String,Object> definedTags;
    /**
     * @return The description of the format entry.
     * 
     */
    private String description;
    /**
     * @return A filter to return only resources that match the specified display name.
     * 
     */
    private String displayName;
    /**
     * @return An array of format entries. The combined output of all the format entries is used for masking.
     * 
     */
    private List<GetLibraryMaskingFormatsLibraryMaskingFormatCollectionItemFormatEntry> formatEntries;
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    private Map<String,Object> freeformTags;
    /**
     * @return The OCID of the library masking format.
     * 
     */
    private String id;
    /**
     * @return An array of OCIDs of the sensitive types compatible with the library masking format.
     * 
     */
    private List<String> sensitiveTypeIds;
    /**
     * @return Specifies whether the library masking format is user-defined or predefined.
     * 
     */
    private String source;
    /**
     * @return A filter to return only the resources that match the specified lifecycle states.
     * 
     */
    private String state;
    /**
     * @return The date and time the library masking format was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339)
     * 
     */
    private String timeCreated;
    /**
     * @return The date and time the library masking format was updated, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339)
     * 
     */
    private String timeUpdated;

    private GetLibraryMaskingFormatsLibraryMaskingFormatCollectionItem() {}
    /**
     * @return A filter to return only resources that match the specified compartment OCID.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Map<String,Object> definedTags() {
        return this.definedTags;
    }
    /**
     * @return The description of the format entry.
     * 
     */
    public String description() {
        return this.description;
    }
    /**
     * @return A filter to return only resources that match the specified display name.
     * 
     */
    public String displayName() {
        return this.displayName;
    }
    /**
     * @return An array of format entries. The combined output of all the format entries is used for masking.
     * 
     */
    public List<GetLibraryMaskingFormatsLibraryMaskingFormatCollectionItemFormatEntry> formatEntries() {
        return this.formatEntries;
    }
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Map<String,Object> freeformTags() {
        return this.freeformTags;
    }
    /**
     * @return The OCID of the library masking format.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return An array of OCIDs of the sensitive types compatible with the library masking format.
     * 
     */
    public List<String> sensitiveTypeIds() {
        return this.sensitiveTypeIds;
    }
    /**
     * @return Specifies whether the library masking format is user-defined or predefined.
     * 
     */
    public String source() {
        return this.source;
    }
    /**
     * @return A filter to return only the resources that match the specified lifecycle states.
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return The date and time the library masking format was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339)
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return The date and time the library masking format was updated, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339)
     * 
     */
    public String timeUpdated() {
        return this.timeUpdated;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetLibraryMaskingFormatsLibraryMaskingFormatCollectionItem defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String compartmentId;
        private Map<String,Object> definedTags;
        private String description;
        private String displayName;
        private List<GetLibraryMaskingFormatsLibraryMaskingFormatCollectionItemFormatEntry> formatEntries;
        private Map<String,Object> freeformTags;
        private String id;
        private List<String> sensitiveTypeIds;
        private String source;
        private String state;
        private String timeCreated;
        private String timeUpdated;
        public Builder() {}
        public Builder(GetLibraryMaskingFormatsLibraryMaskingFormatCollectionItem defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.definedTags = defaults.definedTags;
    	      this.description = defaults.description;
    	      this.displayName = defaults.displayName;
    	      this.formatEntries = defaults.formatEntries;
    	      this.freeformTags = defaults.freeformTags;
    	      this.id = defaults.id;
    	      this.sensitiveTypeIds = defaults.sensitiveTypeIds;
    	      this.source = defaults.source;
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
        public Builder description(String description) {
            this.description = Objects.requireNonNull(description);
            return this;
        }
        @CustomType.Setter
        public Builder displayName(String displayName) {
            this.displayName = Objects.requireNonNull(displayName);
            return this;
        }
        @CustomType.Setter
        public Builder formatEntries(List<GetLibraryMaskingFormatsLibraryMaskingFormatCollectionItemFormatEntry> formatEntries) {
            this.formatEntries = Objects.requireNonNull(formatEntries);
            return this;
        }
        public Builder formatEntries(GetLibraryMaskingFormatsLibraryMaskingFormatCollectionItemFormatEntry... formatEntries) {
            return formatEntries(List.of(formatEntries));
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
        public Builder sensitiveTypeIds(List<String> sensitiveTypeIds) {
            this.sensitiveTypeIds = Objects.requireNonNull(sensitiveTypeIds);
            return this;
        }
        public Builder sensitiveTypeIds(String... sensitiveTypeIds) {
            return sensitiveTypeIds(List.of(sensitiveTypeIds));
        }
        @CustomType.Setter
        public Builder source(String source) {
            this.source = Objects.requireNonNull(source);
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
        public GetLibraryMaskingFormatsLibraryMaskingFormatCollectionItem build() {
            final var o = new GetLibraryMaskingFormatsLibraryMaskingFormatCollectionItem();
            o.compartmentId = compartmentId;
            o.definedTags = definedTags;
            o.description = description;
            o.displayName = displayName;
            o.formatEntries = formatEntries;
            o.freeformTags = freeformTags;
            o.id = id;
            o.sensitiveTypeIds = sensitiveTypeIds;
            o.source = source;
            o.state = state;
            o.timeCreated = timeCreated;
            o.timeUpdated = timeUpdated;
            return o;
        }
    }
}