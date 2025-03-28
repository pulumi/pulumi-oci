// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Limits;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Limits.inputs.QuotaLockArgs;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class QuotaArgs extends com.pulumi.resources.ResourceArgs {

    public static final QuotaArgs Empty = new QuotaArgs();

    /**
     * The OCID of the compartment containing the resource this quota applies to.
     * 
     */
    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    /**
     * @return The OCID of the compartment containing the resource this quota applies to.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }

    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    @Import(name="definedTags")
    private @Nullable Output<Map<String,String>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Optional<Output<Map<String,String>>> definedTags() {
        return Optional.ofNullable(this.definedTags);
    }

    /**
     * (Updatable) The description you assign to the quota.
     * 
     */
    @Import(name="description", required=true)
    private Output<String> description;

    /**
     * @return (Updatable) The description you assign to the quota.
     * 
     */
    public Output<String> description() {
        return this.description;
    }

    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    @Import(name="freeformTags")
    private @Nullable Output<Map<String,String>> freeformTags;

    /**
     * @return (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Optional<Output<Map<String,String>>> freeformTags() {
        return Optional.ofNullable(this.freeformTags);
    }

    /**
     * Locks associated with this resource.
     * 
     */
    @Import(name="locks")
    private @Nullable Output<List<QuotaLockArgs>> locks;

    /**
     * @return Locks associated with this resource.
     * 
     */
    public Optional<Output<List<QuotaLockArgs>>> locks() {
        return Optional.ofNullable(this.locks);
    }

    /**
     * The name you assign to the quota during creation. The name must be unique across all quotas in the tenancy and cannot be changed.
     * 
     */
    @Import(name="name")
    private @Nullable Output<String> name;

    /**
     * @return The name you assign to the quota during creation. The name must be unique across all quotas in the tenancy and cannot be changed.
     * 
     */
    public Optional<Output<String>> name() {
        return Optional.ofNullable(this.name);
    }

    /**
     * (Updatable) An array of quota statements written in the declarative quota statement language.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Import(name="statements", required=true)
    private Output<List<String>> statements;

    /**
     * @return (Updatable) An array of quota statements written in the declarative quota statement language.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Output<List<String>> statements() {
        return this.statements;
    }

    private QuotaArgs() {}

    private QuotaArgs(QuotaArgs $) {
        this.compartmentId = $.compartmentId;
        this.definedTags = $.definedTags;
        this.description = $.description;
        this.freeformTags = $.freeformTags;
        this.locks = $.locks;
        this.name = $.name;
        this.statements = $.statements;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(QuotaArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private QuotaArgs $;

        public Builder() {
            $ = new QuotaArgs();
        }

        public Builder(QuotaArgs defaults) {
            $ = new QuotaArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId The OCID of the compartment containing the resource this quota applies to.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId The OCID of the compartment containing the resource this quota applies to.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(@Nullable Output<Map<String,String>> definedTags) {
            $.definedTags = definedTags;
            return this;
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(Map<String,String> definedTags) {
            return definedTags(Output.of(definedTags));
        }

        /**
         * @param description (Updatable) The description you assign to the quota.
         * 
         * @return builder
         * 
         */
        public Builder description(Output<String> description) {
            $.description = description;
            return this;
        }

        /**
         * @param description (Updatable) The description you assign to the quota.
         * 
         * @return builder
         * 
         */
        public Builder description(String description) {
            return description(Output.of(description));
        }

        /**
         * @param freeformTags (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(@Nullable Output<Map<String,String>> freeformTags) {
            $.freeformTags = freeformTags;
            return this;
        }

        /**
         * @param freeformTags (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(Map<String,String> freeformTags) {
            return freeformTags(Output.of(freeformTags));
        }

        /**
         * @param locks Locks associated with this resource.
         * 
         * @return builder
         * 
         */
        public Builder locks(@Nullable Output<List<QuotaLockArgs>> locks) {
            $.locks = locks;
            return this;
        }

        /**
         * @param locks Locks associated with this resource.
         * 
         * @return builder
         * 
         */
        public Builder locks(List<QuotaLockArgs> locks) {
            return locks(Output.of(locks));
        }

        /**
         * @param locks Locks associated with this resource.
         * 
         * @return builder
         * 
         */
        public Builder locks(QuotaLockArgs... locks) {
            return locks(List.of(locks));
        }

        /**
         * @param name The name you assign to the quota during creation. The name must be unique across all quotas in the tenancy and cannot be changed.
         * 
         * @return builder
         * 
         */
        public Builder name(@Nullable Output<String> name) {
            $.name = name;
            return this;
        }

        /**
         * @param name The name you assign to the quota during creation. The name must be unique across all quotas in the tenancy and cannot be changed.
         * 
         * @return builder
         * 
         */
        public Builder name(String name) {
            return name(Output.of(name));
        }

        /**
         * @param statements (Updatable) An array of quota statements written in the declarative quota statement language.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder statements(Output<List<String>> statements) {
            $.statements = statements;
            return this;
        }

        /**
         * @param statements (Updatable) An array of quota statements written in the declarative quota statement language.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder statements(List<String> statements) {
            return statements(Output.of(statements));
        }

        /**
         * @param statements (Updatable) An array of quota statements written in the declarative quota statement language.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder statements(String... statements) {
            return statements(List.of(statements));
        }

        public QuotaArgs build() {
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("QuotaArgs", "compartmentId");
            }
            if ($.description == null) {
                throw new MissingRequiredPropertyException("QuotaArgs", "description");
            }
            if ($.statements == null) {
                throw new MissingRequiredPropertyException("QuotaArgs", "statements");
            }
            return $;
        }
    }

}
