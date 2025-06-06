// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseManagement;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.DatabaseManagement.inputs.ManagedDatabaseGroupManagedDatabaseArgs;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class ManagedDatabaseGroupArgs extends com.pulumi.resources.ResourceArgs {

    public static final ManagedDatabaseGroupArgs Empty = new ManagedDatabaseGroupArgs();

    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the Managed Database Group resides.
     * 
     */
    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the Managed Database Group resides.
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
     * (Updatable) The information specified by the user about the Managed Database Group.
     * 
     */
    @Import(name="description")
    private @Nullable Output<String> description;

    /**
     * @return (Updatable) The information specified by the user about the Managed Database Group.
     * 
     */
    public Optional<Output<String>> description() {
        return Optional.ofNullable(this.description);
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
     * (Updatable) Set of Managed Databases that the user wants to add to the Managed Database Group. Specifying a block will add the Managed Database to Managed Database Group and removing the block will remove Managed Database from the Managed Database Group.
     * 
     */
    @Import(name="managedDatabases")
    private @Nullable Output<List<ManagedDatabaseGroupManagedDatabaseArgs>> managedDatabases;

    /**
     * @return (Updatable) Set of Managed Databases that the user wants to add to the Managed Database Group. Specifying a block will add the Managed Database to Managed Database Group and removing the block will remove Managed Database from the Managed Database Group.
     * 
     */
    public Optional<Output<List<ManagedDatabaseGroupManagedDatabaseArgs>>> managedDatabases() {
        return Optional.ofNullable(this.managedDatabases);
    }

    /**
     * The name of the Managed Database Group. Valid characters are uppercase or lowercase letters, numbers, and &#34;_&#34;. The name of the Managed Database Group cannot be modified. It must be unique in the compartment and must begin with an alphabetic character.
     * 
     */
    @Import(name="name")
    private @Nullable Output<String> name;

    /**
     * @return The name of the Managed Database Group. Valid characters are uppercase or lowercase letters, numbers, and &#34;_&#34;. The name of the Managed Database Group cannot be modified. It must be unique in the compartment and must begin with an alphabetic character.
     * 
     */
    public Optional<Output<String>> name() {
        return Optional.ofNullable(this.name);
    }

    private ManagedDatabaseGroupArgs() {}

    private ManagedDatabaseGroupArgs(ManagedDatabaseGroupArgs $) {
        this.compartmentId = $.compartmentId;
        this.definedTags = $.definedTags;
        this.description = $.description;
        this.freeformTags = $.freeformTags;
        this.managedDatabases = $.managedDatabases;
        this.name = $.name;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(ManagedDatabaseGroupArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private ManagedDatabaseGroupArgs $;

        public Builder() {
            $ = new ManagedDatabaseGroupArgs();
        }

        public Builder(ManagedDatabaseGroupArgs defaults) {
            $ = new ManagedDatabaseGroupArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the Managed Database Group resides.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the Managed Database Group resides.
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
         * @param description (Updatable) The information specified by the user about the Managed Database Group.
         * 
         * @return builder
         * 
         */
        public Builder description(@Nullable Output<String> description) {
            $.description = description;
            return this;
        }

        /**
         * @param description (Updatable) The information specified by the user about the Managed Database Group.
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
         * @param managedDatabases (Updatable) Set of Managed Databases that the user wants to add to the Managed Database Group. Specifying a block will add the Managed Database to Managed Database Group and removing the block will remove Managed Database from the Managed Database Group.
         * 
         * @return builder
         * 
         */
        public Builder managedDatabases(@Nullable Output<List<ManagedDatabaseGroupManagedDatabaseArgs>> managedDatabases) {
            $.managedDatabases = managedDatabases;
            return this;
        }

        /**
         * @param managedDatabases (Updatable) Set of Managed Databases that the user wants to add to the Managed Database Group. Specifying a block will add the Managed Database to Managed Database Group and removing the block will remove Managed Database from the Managed Database Group.
         * 
         * @return builder
         * 
         */
        public Builder managedDatabases(List<ManagedDatabaseGroupManagedDatabaseArgs> managedDatabases) {
            return managedDatabases(Output.of(managedDatabases));
        }

        /**
         * @param managedDatabases (Updatable) Set of Managed Databases that the user wants to add to the Managed Database Group. Specifying a block will add the Managed Database to Managed Database Group and removing the block will remove Managed Database from the Managed Database Group.
         * 
         * @return builder
         * 
         */
        public Builder managedDatabases(ManagedDatabaseGroupManagedDatabaseArgs... managedDatabases) {
            return managedDatabases(List.of(managedDatabases));
        }

        /**
         * @param name The name of the Managed Database Group. Valid characters are uppercase or lowercase letters, numbers, and &#34;_&#34;. The name of the Managed Database Group cannot be modified. It must be unique in the compartment and must begin with an alphabetic character.
         * 
         * @return builder
         * 
         */
        public Builder name(@Nullable Output<String> name) {
            $.name = name;
            return this;
        }

        /**
         * @param name The name of the Managed Database Group. Valid characters are uppercase or lowercase letters, numbers, and &#34;_&#34;. The name of the Managed Database Group cannot be modified. It must be unique in the compartment and must begin with an alphabetic character.
         * 
         * @return builder
         * 
         */
        public Builder name(String name) {
            return name(Output.of(name));
        }

        public ManagedDatabaseGroupArgs build() {
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("ManagedDatabaseGroupArgs", "compartmentId");
            }
            return $;
        }
    }

}
