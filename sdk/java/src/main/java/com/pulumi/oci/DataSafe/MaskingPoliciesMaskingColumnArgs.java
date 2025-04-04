// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataSafe;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.DataSafe.inputs.MaskingPoliciesMaskingColumnMaskingFormatArgs;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class MaskingPoliciesMaskingColumnArgs extends com.pulumi.resources.ResourceArgs {

    public static final MaskingPoliciesMaskingColumnArgs Empty = new MaskingPoliciesMaskingColumnArgs();

    /**
     * The name of the database column. This attribute cannot be updated for an existing  masking column. Note that the same name is used for the masking column. There  is no separate displayName attribute for the masking column.
     * 
     */
    @Import(name="columnName", required=true)
    private Output<String> columnName;

    /**
     * @return The name of the database column. This attribute cannot be updated for an existing  masking column. Note that the same name is used for the masking column. There  is no separate displayName attribute for the masking column.
     * 
     */
    public Output<String> columnName() {
        return this.columnName;
    }

    /**
     * (Updatable) Indicates whether data masking is enabled for the masking column. Set it to false if  you don&#39;t want to mask the column.
     * 
     */
    @Import(name="isMaskingEnabled")
    private @Nullable Output<Boolean> isMaskingEnabled;

    /**
     * @return (Updatable) Indicates whether data masking is enabled for the masking column. Set it to false if  you don&#39;t want to mask the column.
     * 
     */
    public Optional<Output<Boolean>> isMaskingEnabled() {
        return Optional.ofNullable(this.isMaskingEnabled);
    }

    /**
     * (Updatable) The group of the masking column. It&#39;s a masking group identifier and can be any string  of acceptable length. All the columns in a group are masked together to ensure that  the masked data across these columns continue to retain the same logical relationship.  For more details, check  &lt;a href=https://docs.oracle.com/en/cloud/paas/data-safe/udscs/group-masking1.html#GUID-755056B9-9540-48C0-9491-262A44A85037&gt;Group Masking in the Data Safe documentation.&lt;/a&gt;
     * 
     */
    @Import(name="maskingColumnGroup")
    private @Nullable Output<String> maskingColumnGroup;

    /**
     * @return (Updatable) The group of the masking column. It&#39;s a masking group identifier and can be any string  of acceptable length. All the columns in a group are masked together to ensure that  the masked data across these columns continue to retain the same logical relationship.  For more details, check  &lt;a href=https://docs.oracle.com/en/cloud/paas/data-safe/udscs/group-masking1.html#GUID-755056B9-9540-48C0-9491-262A44A85037&gt;Group Masking in the Data Safe documentation.&lt;/a&gt;
     * 
     */
    public Optional<Output<String>> maskingColumnGroup() {
        return Optional.ofNullable(this.maskingColumnGroup);
    }

    /**
     * (Updatable) The masking formats to be assigned to the masking column. You can specify a condition  as part of each masking format. It enables you to do  &lt;a href=&#34;https://docs.oracle.com/en/cloud/paas/data-safe/udscs/conditional-masking.html&#34;&gt;conditional masking&lt;/a&gt;  so that you can mask the column data values differently using different masking  formats and the associated conditions. A masking format can have one or more format  entries. The combined output of all the format entries is used for masking. It  provides the flexibility to define a masking format that can generate different parts  of a data value separately and then combine them to get the final data value for masking.
     * 
     */
    @Import(name="maskingFormats")
    private @Nullable Output<List<MaskingPoliciesMaskingColumnMaskingFormatArgs>> maskingFormats;

    /**
     * @return (Updatable) The masking formats to be assigned to the masking column. You can specify a condition  as part of each masking format. It enables you to do  &lt;a href=&#34;https://docs.oracle.com/en/cloud/paas/data-safe/udscs/conditional-masking.html&#34;&gt;conditional masking&lt;/a&gt;  so that you can mask the column data values differently using different masking  formats and the associated conditions. A masking format can have one or more format  entries. The combined output of all the format entries is used for masking. It  provides the flexibility to define a masking format that can generate different parts  of a data value separately and then combine them to get the final data value for masking.
     * 
     */
    public Optional<Output<List<MaskingPoliciesMaskingColumnMaskingFormatArgs>>> maskingFormats() {
        return Optional.ofNullable(this.maskingFormats);
    }

    /**
     * The OCID of the masking policy.
     * 
     */
    @Import(name="maskingPolicyId", required=true)
    private Output<String> maskingPolicyId;

    /**
     * @return The OCID of the masking policy.
     * 
     */
    public Output<String> maskingPolicyId() {
        return this.maskingPolicyId;
    }

    /**
     * The name of the object (table or editioning view) that contains the database column. This attribute cannot be updated for an existing masking column.
     * 
     */
    @Import(name="object", required=true)
    private Output<String> object;

    /**
     * @return The name of the object (table or editioning view) that contains the database column. This attribute cannot be updated for an existing masking column.
     * 
     */
    public Output<String> object() {
        return this.object;
    }

    /**
     * (Updatable) The type of the object that contains the database column.
     * 
     */
    @Import(name="objectType")
    private @Nullable Output<String> objectType;

    /**
     * @return (Updatable) The type of the object that contains the database column.
     * 
     */
    public Optional<Output<String>> objectType() {
        return Optional.ofNullable(this.objectType);
    }

    /**
     * The name of the schema that contains the database column. This attribute cannot be updated for an existing masking column.
     * 
     */
    @Import(name="schemaName", required=true)
    private Output<String> schemaName;

    /**
     * @return The name of the schema that contains the database column. This attribute cannot be updated for an existing masking column.
     * 
     */
    public Output<String> schemaName() {
        return this.schemaName;
    }

    /**
     * (Updatable) The OCID of the sensitive type to be associated with the masking column. Note that  if the maskingFormats attribute isn&#39;t provided while creating a masking column,   the default masking format associated with the specified sensitive type is assigned  to the masking column.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Import(name="sensitiveTypeId")
    private @Nullable Output<String> sensitiveTypeId;

    /**
     * @return (Updatable) The OCID of the sensitive type to be associated with the masking column. Note that  if the maskingFormats attribute isn&#39;t provided while creating a masking column,   the default masking format associated with the specified sensitive type is assigned  to the masking column.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Optional<Output<String>> sensitiveTypeId() {
        return Optional.ofNullable(this.sensitiveTypeId);
    }

    private MaskingPoliciesMaskingColumnArgs() {}

    private MaskingPoliciesMaskingColumnArgs(MaskingPoliciesMaskingColumnArgs $) {
        this.columnName = $.columnName;
        this.isMaskingEnabled = $.isMaskingEnabled;
        this.maskingColumnGroup = $.maskingColumnGroup;
        this.maskingFormats = $.maskingFormats;
        this.maskingPolicyId = $.maskingPolicyId;
        this.object = $.object;
        this.objectType = $.objectType;
        this.schemaName = $.schemaName;
        this.sensitiveTypeId = $.sensitiveTypeId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(MaskingPoliciesMaskingColumnArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private MaskingPoliciesMaskingColumnArgs $;

        public Builder() {
            $ = new MaskingPoliciesMaskingColumnArgs();
        }

        public Builder(MaskingPoliciesMaskingColumnArgs defaults) {
            $ = new MaskingPoliciesMaskingColumnArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param columnName The name of the database column. This attribute cannot be updated for an existing  masking column. Note that the same name is used for the masking column. There  is no separate displayName attribute for the masking column.
         * 
         * @return builder
         * 
         */
        public Builder columnName(Output<String> columnName) {
            $.columnName = columnName;
            return this;
        }

        /**
         * @param columnName The name of the database column. This attribute cannot be updated for an existing  masking column. Note that the same name is used for the masking column. There  is no separate displayName attribute for the masking column.
         * 
         * @return builder
         * 
         */
        public Builder columnName(String columnName) {
            return columnName(Output.of(columnName));
        }

        /**
         * @param isMaskingEnabled (Updatable) Indicates whether data masking is enabled for the masking column. Set it to false if  you don&#39;t want to mask the column.
         * 
         * @return builder
         * 
         */
        public Builder isMaskingEnabled(@Nullable Output<Boolean> isMaskingEnabled) {
            $.isMaskingEnabled = isMaskingEnabled;
            return this;
        }

        /**
         * @param isMaskingEnabled (Updatable) Indicates whether data masking is enabled for the masking column. Set it to false if  you don&#39;t want to mask the column.
         * 
         * @return builder
         * 
         */
        public Builder isMaskingEnabled(Boolean isMaskingEnabled) {
            return isMaskingEnabled(Output.of(isMaskingEnabled));
        }

        /**
         * @param maskingColumnGroup (Updatable) The group of the masking column. It&#39;s a masking group identifier and can be any string  of acceptable length. All the columns in a group are masked together to ensure that  the masked data across these columns continue to retain the same logical relationship.  For more details, check  &lt;a href=https://docs.oracle.com/en/cloud/paas/data-safe/udscs/group-masking1.html#GUID-755056B9-9540-48C0-9491-262A44A85037&gt;Group Masking in the Data Safe documentation.&lt;/a&gt;
         * 
         * @return builder
         * 
         */
        public Builder maskingColumnGroup(@Nullable Output<String> maskingColumnGroup) {
            $.maskingColumnGroup = maskingColumnGroup;
            return this;
        }

        /**
         * @param maskingColumnGroup (Updatable) The group of the masking column. It&#39;s a masking group identifier and can be any string  of acceptable length. All the columns in a group are masked together to ensure that  the masked data across these columns continue to retain the same logical relationship.  For more details, check  &lt;a href=https://docs.oracle.com/en/cloud/paas/data-safe/udscs/group-masking1.html#GUID-755056B9-9540-48C0-9491-262A44A85037&gt;Group Masking in the Data Safe documentation.&lt;/a&gt;
         * 
         * @return builder
         * 
         */
        public Builder maskingColumnGroup(String maskingColumnGroup) {
            return maskingColumnGroup(Output.of(maskingColumnGroup));
        }

        /**
         * @param maskingFormats (Updatable) The masking formats to be assigned to the masking column. You can specify a condition  as part of each masking format. It enables you to do  &lt;a href=&#34;https://docs.oracle.com/en/cloud/paas/data-safe/udscs/conditional-masking.html&#34;&gt;conditional masking&lt;/a&gt;  so that you can mask the column data values differently using different masking  formats and the associated conditions. A masking format can have one or more format  entries. The combined output of all the format entries is used for masking. It  provides the flexibility to define a masking format that can generate different parts  of a data value separately and then combine them to get the final data value for masking.
         * 
         * @return builder
         * 
         */
        public Builder maskingFormats(@Nullable Output<List<MaskingPoliciesMaskingColumnMaskingFormatArgs>> maskingFormats) {
            $.maskingFormats = maskingFormats;
            return this;
        }

        /**
         * @param maskingFormats (Updatable) The masking formats to be assigned to the masking column. You can specify a condition  as part of each masking format. It enables you to do  &lt;a href=&#34;https://docs.oracle.com/en/cloud/paas/data-safe/udscs/conditional-masking.html&#34;&gt;conditional masking&lt;/a&gt;  so that you can mask the column data values differently using different masking  formats and the associated conditions. A masking format can have one or more format  entries. The combined output of all the format entries is used for masking. It  provides the flexibility to define a masking format that can generate different parts  of a data value separately and then combine them to get the final data value for masking.
         * 
         * @return builder
         * 
         */
        public Builder maskingFormats(List<MaskingPoliciesMaskingColumnMaskingFormatArgs> maskingFormats) {
            return maskingFormats(Output.of(maskingFormats));
        }

        /**
         * @param maskingFormats (Updatable) The masking formats to be assigned to the masking column. You can specify a condition  as part of each masking format. It enables you to do  &lt;a href=&#34;https://docs.oracle.com/en/cloud/paas/data-safe/udscs/conditional-masking.html&#34;&gt;conditional masking&lt;/a&gt;  so that you can mask the column data values differently using different masking  formats and the associated conditions. A masking format can have one or more format  entries. The combined output of all the format entries is used for masking. It  provides the flexibility to define a masking format that can generate different parts  of a data value separately and then combine them to get the final data value for masking.
         * 
         * @return builder
         * 
         */
        public Builder maskingFormats(MaskingPoliciesMaskingColumnMaskingFormatArgs... maskingFormats) {
            return maskingFormats(List.of(maskingFormats));
        }

        /**
         * @param maskingPolicyId The OCID of the masking policy.
         * 
         * @return builder
         * 
         */
        public Builder maskingPolicyId(Output<String> maskingPolicyId) {
            $.maskingPolicyId = maskingPolicyId;
            return this;
        }

        /**
         * @param maskingPolicyId The OCID of the masking policy.
         * 
         * @return builder
         * 
         */
        public Builder maskingPolicyId(String maskingPolicyId) {
            return maskingPolicyId(Output.of(maskingPolicyId));
        }

        /**
         * @param object The name of the object (table or editioning view) that contains the database column. This attribute cannot be updated for an existing masking column.
         * 
         * @return builder
         * 
         */
        public Builder object(Output<String> object) {
            $.object = object;
            return this;
        }

        /**
         * @param object The name of the object (table or editioning view) that contains the database column. This attribute cannot be updated for an existing masking column.
         * 
         * @return builder
         * 
         */
        public Builder object(String object) {
            return object(Output.of(object));
        }

        /**
         * @param objectType (Updatable) The type of the object that contains the database column.
         * 
         * @return builder
         * 
         */
        public Builder objectType(@Nullable Output<String> objectType) {
            $.objectType = objectType;
            return this;
        }

        /**
         * @param objectType (Updatable) The type of the object that contains the database column.
         * 
         * @return builder
         * 
         */
        public Builder objectType(String objectType) {
            return objectType(Output.of(objectType));
        }

        /**
         * @param schemaName The name of the schema that contains the database column. This attribute cannot be updated for an existing masking column.
         * 
         * @return builder
         * 
         */
        public Builder schemaName(Output<String> schemaName) {
            $.schemaName = schemaName;
            return this;
        }

        /**
         * @param schemaName The name of the schema that contains the database column. This attribute cannot be updated for an existing masking column.
         * 
         * @return builder
         * 
         */
        public Builder schemaName(String schemaName) {
            return schemaName(Output.of(schemaName));
        }

        /**
         * @param sensitiveTypeId (Updatable) The OCID of the sensitive type to be associated with the masking column. Note that  if the maskingFormats attribute isn&#39;t provided while creating a masking column,   the default masking format associated with the specified sensitive type is assigned  to the masking column.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder sensitiveTypeId(@Nullable Output<String> sensitiveTypeId) {
            $.sensitiveTypeId = sensitiveTypeId;
            return this;
        }

        /**
         * @param sensitiveTypeId (Updatable) The OCID of the sensitive type to be associated with the masking column. Note that  if the maskingFormats attribute isn&#39;t provided while creating a masking column,   the default masking format associated with the specified sensitive type is assigned  to the masking column.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder sensitiveTypeId(String sensitiveTypeId) {
            return sensitiveTypeId(Output.of(sensitiveTypeId));
        }

        public MaskingPoliciesMaskingColumnArgs build() {
            if ($.columnName == null) {
                throw new MissingRequiredPropertyException("MaskingPoliciesMaskingColumnArgs", "columnName");
            }
            if ($.maskingPolicyId == null) {
                throw new MissingRequiredPropertyException("MaskingPoliciesMaskingColumnArgs", "maskingPolicyId");
            }
            if ($.object == null) {
                throw new MissingRequiredPropertyException("MaskingPoliciesMaskingColumnArgs", "object");
            }
            if ($.schemaName == null) {
                throw new MissingRequiredPropertyException("MaskingPoliciesMaskingColumnArgs", "schemaName");
            }
            return $;
        }
    }

}
