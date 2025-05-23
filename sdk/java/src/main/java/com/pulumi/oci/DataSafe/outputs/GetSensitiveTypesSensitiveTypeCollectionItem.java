// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataSafe.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Boolean;
import java.lang.String;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetSensitiveTypesSensitiveTypeCollectionItem {
    /**
     * @return A regular expression to be used by data discovery for matching column comments.
     * 
     */
    private String commentPattern;
    /**
     * @return A filter to return only resources that match the specified compartment OCID.
     * 
     */
    private String compartmentId;
    /**
     * @return A regular expression to be used by data discovery for matching column data values.
     * 
     */
    private String dataPattern;
    /**
     * @return A filter to return only the sensitive types that have the default masking format identified by the specified OCID.
     * 
     */
    private String defaultMaskingFormatId;
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm) Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    private Map<String,String> definedTags;
    /**
     * @return The description of the sensitive type.
     * 
     */
    private String description;
    /**
     * @return A filter to return only resources that match the specified display name.
     * 
     */
    private String displayName;
    /**
     * @return A filter to return the sensitive type resources based on the value of their entityType attribute.
     * 
     */
    private String entityType;
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    private Map<String,String> freeformTags;
    /**
     * @return The OCID of the sensitive type.
     * 
     */
    private String id;
    /**
     * @return A filter to return only the common sensitive type resources. Common sensitive types belong to  library sensitive types which are frequently used to perform sensitive data discovery.
     * 
     */
    private Boolean isCommon;
    /**
     * @return A regular expression to be used by data discovery for matching column names.
     * 
     */
    private String namePattern;
    /**
     * @return A filter to return only the sensitive types that are children of the sensitive category identified by the specified OCID.
     * 
     */
    private String parentCategoryId;
    /**
     * @return The search type indicating how the column name, comment and data patterns should be used by data discovery. [Learn more](https://docs.oracle.com/en/cloud/paas/data-safe/udscs/sensitive-types.html#GUID-1D1AD98E-B93F-4FF2-80AE-CB7D8A14F6CC).
     * 
     */
    private String searchType;
    /**
     * @return The short name of the sensitive type.
     * 
     */
    private String shortName;
    /**
     * @return Specifies whether the sensitive type is user-defined or predefined.
     * 
     */
    private String source;
    /**
     * @return A filter to return only the resources that match the specified lifecycle state.
     * 
     */
    private String state;
    /**
     * @return System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    private Map<String,String> systemTags;
    /**
     * @return The date and time the sensitive type was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
     * 
     */
    private String timeCreated;
    /**
     * @return The date and time the sensitive type was last updated, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
     * 
     */
    private String timeUpdated;

    private GetSensitiveTypesSensitiveTypeCollectionItem() {}
    /**
     * @return A regular expression to be used by data discovery for matching column comments.
     * 
     */
    public String commentPattern() {
        return this.commentPattern;
    }
    /**
     * @return A filter to return only resources that match the specified compartment OCID.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return A regular expression to be used by data discovery for matching column data values.
     * 
     */
    public String dataPattern() {
        return this.dataPattern;
    }
    /**
     * @return A filter to return only the sensitive types that have the default masking format identified by the specified OCID.
     * 
     */
    public String defaultMaskingFormatId() {
        return this.defaultMaskingFormatId;
    }
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm) Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Map<String,String> definedTags() {
        return this.definedTags;
    }
    /**
     * @return The description of the sensitive type.
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
     * @return A filter to return the sensitive type resources based on the value of their entityType attribute.
     * 
     */
    public String entityType() {
        return this.entityType;
    }
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Map<String,String> freeformTags() {
        return this.freeformTags;
    }
    /**
     * @return The OCID of the sensitive type.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return A filter to return only the common sensitive type resources. Common sensitive types belong to  library sensitive types which are frequently used to perform sensitive data discovery.
     * 
     */
    public Boolean isCommon() {
        return this.isCommon;
    }
    /**
     * @return A regular expression to be used by data discovery for matching column names.
     * 
     */
    public String namePattern() {
        return this.namePattern;
    }
    /**
     * @return A filter to return only the sensitive types that are children of the sensitive category identified by the specified OCID.
     * 
     */
    public String parentCategoryId() {
        return this.parentCategoryId;
    }
    /**
     * @return The search type indicating how the column name, comment and data patterns should be used by data discovery. [Learn more](https://docs.oracle.com/en/cloud/paas/data-safe/udscs/sensitive-types.html#GUID-1D1AD98E-B93F-4FF2-80AE-CB7D8A14F6CC).
     * 
     */
    public String searchType() {
        return this.searchType;
    }
    /**
     * @return The short name of the sensitive type.
     * 
     */
    public String shortName() {
        return this.shortName;
    }
    /**
     * @return Specifies whether the sensitive type is user-defined or predefined.
     * 
     */
    public String source() {
        return this.source;
    }
    /**
     * @return A filter to return only the resources that match the specified lifecycle state.
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    public Map<String,String> systemTags() {
        return this.systemTags;
    }
    /**
     * @return The date and time the sensitive type was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return The date and time the sensitive type was last updated, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
     * 
     */
    public String timeUpdated() {
        return this.timeUpdated;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetSensitiveTypesSensitiveTypeCollectionItem defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String commentPattern;
        private String compartmentId;
        private String dataPattern;
        private String defaultMaskingFormatId;
        private Map<String,String> definedTags;
        private String description;
        private String displayName;
        private String entityType;
        private Map<String,String> freeformTags;
        private String id;
        private Boolean isCommon;
        private String namePattern;
        private String parentCategoryId;
        private String searchType;
        private String shortName;
        private String source;
        private String state;
        private Map<String,String> systemTags;
        private String timeCreated;
        private String timeUpdated;
        public Builder() {}
        public Builder(GetSensitiveTypesSensitiveTypeCollectionItem defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.commentPattern = defaults.commentPattern;
    	      this.compartmentId = defaults.compartmentId;
    	      this.dataPattern = defaults.dataPattern;
    	      this.defaultMaskingFormatId = defaults.defaultMaskingFormatId;
    	      this.definedTags = defaults.definedTags;
    	      this.description = defaults.description;
    	      this.displayName = defaults.displayName;
    	      this.entityType = defaults.entityType;
    	      this.freeformTags = defaults.freeformTags;
    	      this.id = defaults.id;
    	      this.isCommon = defaults.isCommon;
    	      this.namePattern = defaults.namePattern;
    	      this.parentCategoryId = defaults.parentCategoryId;
    	      this.searchType = defaults.searchType;
    	      this.shortName = defaults.shortName;
    	      this.source = defaults.source;
    	      this.state = defaults.state;
    	      this.systemTags = defaults.systemTags;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeUpdated = defaults.timeUpdated;
        }

        @CustomType.Setter
        public Builder commentPattern(String commentPattern) {
            if (commentPattern == null) {
              throw new MissingRequiredPropertyException("GetSensitiveTypesSensitiveTypeCollectionItem", "commentPattern");
            }
            this.commentPattern = commentPattern;
            return this;
        }
        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            if (compartmentId == null) {
              throw new MissingRequiredPropertyException("GetSensitiveTypesSensitiveTypeCollectionItem", "compartmentId");
            }
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder dataPattern(String dataPattern) {
            if (dataPattern == null) {
              throw new MissingRequiredPropertyException("GetSensitiveTypesSensitiveTypeCollectionItem", "dataPattern");
            }
            this.dataPattern = dataPattern;
            return this;
        }
        @CustomType.Setter
        public Builder defaultMaskingFormatId(String defaultMaskingFormatId) {
            if (defaultMaskingFormatId == null) {
              throw new MissingRequiredPropertyException("GetSensitiveTypesSensitiveTypeCollectionItem", "defaultMaskingFormatId");
            }
            this.defaultMaskingFormatId = defaultMaskingFormatId;
            return this;
        }
        @CustomType.Setter
        public Builder definedTags(Map<String,String> definedTags) {
            if (definedTags == null) {
              throw new MissingRequiredPropertyException("GetSensitiveTypesSensitiveTypeCollectionItem", "definedTags");
            }
            this.definedTags = definedTags;
            return this;
        }
        @CustomType.Setter
        public Builder description(String description) {
            if (description == null) {
              throw new MissingRequiredPropertyException("GetSensitiveTypesSensitiveTypeCollectionItem", "description");
            }
            this.description = description;
            return this;
        }
        @CustomType.Setter
        public Builder displayName(String displayName) {
            if (displayName == null) {
              throw new MissingRequiredPropertyException("GetSensitiveTypesSensitiveTypeCollectionItem", "displayName");
            }
            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder entityType(String entityType) {
            if (entityType == null) {
              throw new MissingRequiredPropertyException("GetSensitiveTypesSensitiveTypeCollectionItem", "entityType");
            }
            this.entityType = entityType;
            return this;
        }
        @CustomType.Setter
        public Builder freeformTags(Map<String,String> freeformTags) {
            if (freeformTags == null) {
              throw new MissingRequiredPropertyException("GetSensitiveTypesSensitiveTypeCollectionItem", "freeformTags");
            }
            this.freeformTags = freeformTags;
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetSensitiveTypesSensitiveTypeCollectionItem", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder isCommon(Boolean isCommon) {
            if (isCommon == null) {
              throw new MissingRequiredPropertyException("GetSensitiveTypesSensitiveTypeCollectionItem", "isCommon");
            }
            this.isCommon = isCommon;
            return this;
        }
        @CustomType.Setter
        public Builder namePattern(String namePattern) {
            if (namePattern == null) {
              throw new MissingRequiredPropertyException("GetSensitiveTypesSensitiveTypeCollectionItem", "namePattern");
            }
            this.namePattern = namePattern;
            return this;
        }
        @CustomType.Setter
        public Builder parentCategoryId(String parentCategoryId) {
            if (parentCategoryId == null) {
              throw new MissingRequiredPropertyException("GetSensitiveTypesSensitiveTypeCollectionItem", "parentCategoryId");
            }
            this.parentCategoryId = parentCategoryId;
            return this;
        }
        @CustomType.Setter
        public Builder searchType(String searchType) {
            if (searchType == null) {
              throw new MissingRequiredPropertyException("GetSensitiveTypesSensitiveTypeCollectionItem", "searchType");
            }
            this.searchType = searchType;
            return this;
        }
        @CustomType.Setter
        public Builder shortName(String shortName) {
            if (shortName == null) {
              throw new MissingRequiredPropertyException("GetSensitiveTypesSensitiveTypeCollectionItem", "shortName");
            }
            this.shortName = shortName;
            return this;
        }
        @CustomType.Setter
        public Builder source(String source) {
            if (source == null) {
              throw new MissingRequiredPropertyException("GetSensitiveTypesSensitiveTypeCollectionItem", "source");
            }
            this.source = source;
            return this;
        }
        @CustomType.Setter
        public Builder state(String state) {
            if (state == null) {
              throw new MissingRequiredPropertyException("GetSensitiveTypesSensitiveTypeCollectionItem", "state");
            }
            this.state = state;
            return this;
        }
        @CustomType.Setter
        public Builder systemTags(Map<String,String> systemTags) {
            if (systemTags == null) {
              throw new MissingRequiredPropertyException("GetSensitiveTypesSensitiveTypeCollectionItem", "systemTags");
            }
            this.systemTags = systemTags;
            return this;
        }
        @CustomType.Setter
        public Builder timeCreated(String timeCreated) {
            if (timeCreated == null) {
              throw new MissingRequiredPropertyException("GetSensitiveTypesSensitiveTypeCollectionItem", "timeCreated");
            }
            this.timeCreated = timeCreated;
            return this;
        }
        @CustomType.Setter
        public Builder timeUpdated(String timeUpdated) {
            if (timeUpdated == null) {
              throw new MissingRequiredPropertyException("GetSensitiveTypesSensitiveTypeCollectionItem", "timeUpdated");
            }
            this.timeUpdated = timeUpdated;
            return this;
        }
        public GetSensitiveTypesSensitiveTypeCollectionItem build() {
            final var _resultValue = new GetSensitiveTypesSensitiveTypeCollectionItem();
            _resultValue.commentPattern = commentPattern;
            _resultValue.compartmentId = compartmentId;
            _resultValue.dataPattern = dataPattern;
            _resultValue.defaultMaskingFormatId = defaultMaskingFormatId;
            _resultValue.definedTags = definedTags;
            _resultValue.description = description;
            _resultValue.displayName = displayName;
            _resultValue.entityType = entityType;
            _resultValue.freeformTags = freeformTags;
            _resultValue.id = id;
            _resultValue.isCommon = isCommon;
            _resultValue.namePattern = namePattern;
            _resultValue.parentCategoryId = parentCategoryId;
            _resultValue.searchType = searchType;
            _resultValue.shortName = shortName;
            _resultValue.source = source;
            _resultValue.state = state;
            _resultValue.systemTags = systemTags;
            _resultValue.timeCreated = timeCreated;
            _resultValue.timeUpdated = timeUpdated;
            return _resultValue;
        }
    }
}
