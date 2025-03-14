// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataSafe;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class SensitiveTypeArgs extends com.pulumi.resources.ResourceArgs {

    public static final SensitiveTypeArgs Empty = new SensitiveTypeArgs();

    /**
     * (Updatable) A regular expression to be used by data discovery for matching column comments.
     * 
     */
    @Import(name="commentPattern")
    private @Nullable Output<String> commentPattern;

    /**
     * @return (Updatable) A regular expression to be used by data discovery for matching column comments.
     * 
     */
    public Optional<Output<String>> commentPattern() {
        return Optional.ofNullable(this.commentPattern);
    }

    /**
     * (Updatable) The OCID of the compartment where the sensitive type should be created.
     * 
     */
    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    /**
     * @return (Updatable) The OCID of the compartment where the sensitive type should be created.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }

    /**
     * (Updatable) A regular expression to be used by data discovery for matching column data values.
     * 
     */
    @Import(name="dataPattern")
    private @Nullable Output<String> dataPattern;

    /**
     * @return (Updatable) A regular expression to be used by data discovery for matching column data values.
     * 
     */
    public Optional<Output<String>> dataPattern() {
        return Optional.ofNullable(this.dataPattern);
    }

    /**
     * (Updatable) The OCID of the library masking format that should be used to mask the sensitive columns associated with the sensitive type.
     * 
     */
    @Import(name="defaultMaskingFormatId")
    private @Nullable Output<String> defaultMaskingFormatId;

    /**
     * @return (Updatable) The OCID of the library masking format that should be used to mask the sensitive columns associated with the sensitive type.
     * 
     */
    public Optional<Output<String>> defaultMaskingFormatId() {
        return Optional.ofNullable(this.defaultMaskingFormatId);
    }

    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm) Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    @Import(name="definedTags")
    private @Nullable Output<Map<String,String>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm) Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Optional<Output<Map<String,String>>> definedTags() {
        return Optional.ofNullable(this.definedTags);
    }

    /**
     * (Updatable) The description of the sensitive type.
     * 
     */
    @Import(name="description")
    private @Nullable Output<String> description;

    /**
     * @return (Updatable) The description of the sensitive type.
     * 
     */
    public Optional<Output<String>> description() {
        return Optional.ofNullable(this.description);
    }

    /**
     * (Updatable) The display name of the sensitive type. The name does not have to be unique, and it&#39;s changeable.
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return (Updatable) The display name of the sensitive type. The name does not have to be unique, and it&#39;s changeable.
     * 
     */
    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    /**
     * (Updatable) The entity type. It can be either a sensitive type with regular expressions or a sensitive category used for grouping similar sensitive types.
     * 
     */
    @Import(name="entityType", required=true)
    private Output<String> entityType;

    /**
     * @return (Updatable) The entity type. It can be either a sensitive type with regular expressions or a sensitive category used for grouping similar sensitive types.
     * 
     */
    public Output<String> entityType() {
        return this.entityType;
    }

    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    @Import(name="freeformTags")
    private @Nullable Output<Map<String,String>> freeformTags;

    /**
     * @return (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Optional<Output<Map<String,String>>> freeformTags() {
        return Optional.ofNullable(this.freeformTags);
    }

    /**
     * (Updatable) A regular expression to be used by data discovery for matching column names.
     * 
     */
    @Import(name="namePattern")
    private @Nullable Output<String> namePattern;

    /**
     * @return (Updatable) A regular expression to be used by data discovery for matching column names.
     * 
     */
    public Optional<Output<String>> namePattern() {
        return Optional.ofNullable(this.namePattern);
    }

    /**
     * (Updatable) The OCID of the parent sensitive category.
     * 
     */
    @Import(name="parentCategoryId")
    private @Nullable Output<String> parentCategoryId;

    /**
     * @return (Updatable) The OCID of the parent sensitive category.
     * 
     */
    public Optional<Output<String>> parentCategoryId() {
        return Optional.ofNullable(this.parentCategoryId);
    }

    /**
     * (Updatable) The search type indicating how the column name, comment and data patterns should be used by data discovery. [Learn more](https://docs.oracle.com/en/cloud/paas/data-safe/udscs/sensitive-types.html#GUID-1D1AD98E-B93F-4FF2-80AE-CB7D8A14F6CC).
     * 
     */
    @Import(name="searchType")
    private @Nullable Output<String> searchType;

    /**
     * @return (Updatable) The search type indicating how the column name, comment and data patterns should be used by data discovery. [Learn more](https://docs.oracle.com/en/cloud/paas/data-safe/udscs/sensitive-types.html#GUID-1D1AD98E-B93F-4FF2-80AE-CB7D8A14F6CC).
     * 
     */
    public Optional<Output<String>> searchType() {
        return Optional.ofNullable(this.searchType);
    }

    /**
     * (Updatable) The short name of the sensitive type.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Import(name="shortName")
    private @Nullable Output<String> shortName;

    /**
     * @return (Updatable) The short name of the sensitive type.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Optional<Output<String>> shortName() {
        return Optional.ofNullable(this.shortName);
    }

    private SensitiveTypeArgs() {}

    private SensitiveTypeArgs(SensitiveTypeArgs $) {
        this.commentPattern = $.commentPattern;
        this.compartmentId = $.compartmentId;
        this.dataPattern = $.dataPattern;
        this.defaultMaskingFormatId = $.defaultMaskingFormatId;
        this.definedTags = $.definedTags;
        this.description = $.description;
        this.displayName = $.displayName;
        this.entityType = $.entityType;
        this.freeformTags = $.freeformTags;
        this.namePattern = $.namePattern;
        this.parentCategoryId = $.parentCategoryId;
        this.searchType = $.searchType;
        this.shortName = $.shortName;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(SensitiveTypeArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private SensitiveTypeArgs $;

        public Builder() {
            $ = new SensitiveTypeArgs();
        }

        public Builder(SensitiveTypeArgs defaults) {
            $ = new SensitiveTypeArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param commentPattern (Updatable) A regular expression to be used by data discovery for matching column comments.
         * 
         * @return builder
         * 
         */
        public Builder commentPattern(@Nullable Output<String> commentPattern) {
            $.commentPattern = commentPattern;
            return this;
        }

        /**
         * @param commentPattern (Updatable) A regular expression to be used by data discovery for matching column comments.
         * 
         * @return builder
         * 
         */
        public Builder commentPattern(String commentPattern) {
            return commentPattern(Output.of(commentPattern));
        }

        /**
         * @param compartmentId (Updatable) The OCID of the compartment where the sensitive type should be created.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId (Updatable) The OCID of the compartment where the sensitive type should be created.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param dataPattern (Updatable) A regular expression to be used by data discovery for matching column data values.
         * 
         * @return builder
         * 
         */
        public Builder dataPattern(@Nullable Output<String> dataPattern) {
            $.dataPattern = dataPattern;
            return this;
        }

        /**
         * @param dataPattern (Updatable) A regular expression to be used by data discovery for matching column data values.
         * 
         * @return builder
         * 
         */
        public Builder dataPattern(String dataPattern) {
            return dataPattern(Output.of(dataPattern));
        }

        /**
         * @param defaultMaskingFormatId (Updatable) The OCID of the library masking format that should be used to mask the sensitive columns associated with the sensitive type.
         * 
         * @return builder
         * 
         */
        public Builder defaultMaskingFormatId(@Nullable Output<String> defaultMaskingFormatId) {
            $.defaultMaskingFormatId = defaultMaskingFormatId;
            return this;
        }

        /**
         * @param defaultMaskingFormatId (Updatable) The OCID of the library masking format that should be used to mask the sensitive columns associated with the sensitive type.
         * 
         * @return builder
         * 
         */
        public Builder defaultMaskingFormatId(String defaultMaskingFormatId) {
            return defaultMaskingFormatId(Output.of(defaultMaskingFormatId));
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm) Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(@Nullable Output<Map<String,String>> definedTags) {
            $.definedTags = definedTags;
            return this;
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm) Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(Map<String,String> definedTags) {
            return definedTags(Output.of(definedTags));
        }

        /**
         * @param description (Updatable) The description of the sensitive type.
         * 
         * @return builder
         * 
         */
        public Builder description(@Nullable Output<String> description) {
            $.description = description;
            return this;
        }

        /**
         * @param description (Updatable) The description of the sensitive type.
         * 
         * @return builder
         * 
         */
        public Builder description(String description) {
            return description(Output.of(description));
        }

        /**
         * @param displayName (Updatable) The display name of the sensitive type. The name does not have to be unique, and it&#39;s changeable.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName (Updatable) The display name of the sensitive type. The name does not have to be unique, and it&#39;s changeable.
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        /**
         * @param entityType (Updatable) The entity type. It can be either a sensitive type with regular expressions or a sensitive category used for grouping similar sensitive types.
         * 
         * @return builder
         * 
         */
        public Builder entityType(Output<String> entityType) {
            $.entityType = entityType;
            return this;
        }

        /**
         * @param entityType (Updatable) The entity type. It can be either a sensitive type with regular expressions or a sensitive category used for grouping similar sensitive types.
         * 
         * @return builder
         * 
         */
        public Builder entityType(String entityType) {
            return entityType(Output.of(entityType));
        }

        /**
         * @param freeformTags (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(@Nullable Output<Map<String,String>> freeformTags) {
            $.freeformTags = freeformTags;
            return this;
        }

        /**
         * @param freeformTags (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(Map<String,String> freeformTags) {
            return freeformTags(Output.of(freeformTags));
        }

        /**
         * @param namePattern (Updatable) A regular expression to be used by data discovery for matching column names.
         * 
         * @return builder
         * 
         */
        public Builder namePattern(@Nullable Output<String> namePattern) {
            $.namePattern = namePattern;
            return this;
        }

        /**
         * @param namePattern (Updatable) A regular expression to be used by data discovery for matching column names.
         * 
         * @return builder
         * 
         */
        public Builder namePattern(String namePattern) {
            return namePattern(Output.of(namePattern));
        }

        /**
         * @param parentCategoryId (Updatable) The OCID of the parent sensitive category.
         * 
         * @return builder
         * 
         */
        public Builder parentCategoryId(@Nullable Output<String> parentCategoryId) {
            $.parentCategoryId = parentCategoryId;
            return this;
        }

        /**
         * @param parentCategoryId (Updatable) The OCID of the parent sensitive category.
         * 
         * @return builder
         * 
         */
        public Builder parentCategoryId(String parentCategoryId) {
            return parentCategoryId(Output.of(parentCategoryId));
        }

        /**
         * @param searchType (Updatable) The search type indicating how the column name, comment and data patterns should be used by data discovery. [Learn more](https://docs.oracle.com/en/cloud/paas/data-safe/udscs/sensitive-types.html#GUID-1D1AD98E-B93F-4FF2-80AE-CB7D8A14F6CC).
         * 
         * @return builder
         * 
         */
        public Builder searchType(@Nullable Output<String> searchType) {
            $.searchType = searchType;
            return this;
        }

        /**
         * @param searchType (Updatable) The search type indicating how the column name, comment and data patterns should be used by data discovery. [Learn more](https://docs.oracle.com/en/cloud/paas/data-safe/udscs/sensitive-types.html#GUID-1D1AD98E-B93F-4FF2-80AE-CB7D8A14F6CC).
         * 
         * @return builder
         * 
         */
        public Builder searchType(String searchType) {
            return searchType(Output.of(searchType));
        }

        /**
         * @param shortName (Updatable) The short name of the sensitive type.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder shortName(@Nullable Output<String> shortName) {
            $.shortName = shortName;
            return this;
        }

        /**
         * @param shortName (Updatable) The short name of the sensitive type.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder shortName(String shortName) {
            return shortName(Output.of(shortName));
        }

        public SensitiveTypeArgs build() {
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("SensitiveTypeArgs", "compartmentId");
            }
            if ($.entityType == null) {
                throw new MissingRequiredPropertyException("SensitiveTypeArgs", "entityType");
            }
            return $;
        }
    }

}
